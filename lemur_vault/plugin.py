import requests
import math

from lemur.plugins import lemur_vault
from lemur.plugins.bases.issuer import IssuerPlugin
from flask import current_app


def process_sign_options(options, csr):
    data = '{"format":"pem", "common_name": "' + options['common_name'] + '"'

    if csr:
        data += ', "csr": "' + csr.decode('utf-8').replace('\n', '\\n') + '"'

    alt_names = options['extensions']['sub_alt_names']['names']
    dns_names = ''
    ip_sans = ''

    for name in alt_names:
        if name['name_type'] == 'DNSName':
            dns_names += name['value'] + ', '
        if name['name_type'] == 'IPAddress':
            ip_sans += name['value'] + ', '

    if dns_names != '':
        data += ', "alt_names": "' + dns_names[:-2] + '"'
    if ip_sans != '':
        data += ', "ip_sans": "' + ip_sans[:-2] + '"'

	is_valid, ttl = validate_ttl(options)
	if is_valid:	
		data += ', "ttl": "' + ttl + 'h"'

    data += '}'

    return data


def validate_ttl(options):
    if options['validity_end'] and options['validity_start']:
        ttl = math.floor(abs(options['validity_end'] - options['validity_start']).total_seconds() / 3600)
    elif options['validity_years']:
        ttl = options['validity_years'] * 365 * 24
	try:
		resp = requests.get(current_app.get('VAULT_BASE_URL' + '/v1/pki/roles/' + options['Authority'].name
		
		if resp.status_code != 200:
			current_config.logger.info('Vault: Can\'t access role configuration.')
			raise Exception('Vault: Can\'t access role configuration.')

		max_ttl = resp.json()['max_ttl']
		
		if int(max_ttl[:-1]) < ttl
			current_app.logger.info('Certificate TTL is above max ttl - ' + max_ttl)
			return False, -1
		else:
			return True, ttl
				
    except ConnectionError as ConnError:
        current_app.logger.info('There was an error while connecting to Vault server.')
        raise ConnError	


def process_role_options(options):
    data = '{"allow_subdomains":"true", "allow_any_name":"true"'

    if options['key_type']:
        data += ',"key_type":"' + options['key_type'][:3].lower() + '", "key_bits":"' + options['key_type'][-4:] + '"'

    key_usage = ',"key_usage":"'
    if options['extensions']:
        if options['extensions']['key_usage']:
            if options['extensions']['key_usage']['use_digital_signature']:
                key_usage += 'DigitalSignature,'
            if options['extensions']['key_usage']['use_key_encipherment']:
                key_usage += 'KeyEncipherment,'
        data += key_usage + 'KeyEncipherment"'

    if options['validity_end'] and options['validity_start']:
        ttl = math.floor(abs(options['validity_end'] - options['validity_start']).total_seconds() / 3600)
    elif options['validity_years']:
        ttl = options['validity_years'] * 365 * 24

    data += ',"ttl":"' + str(ttl) + 'h", "max_ttl":"' + str(ttl) + 'h"'
    data += '}'

    return data


def create_vault_role(options):
    url = current_app.config.get('VAULT_ROLES_URL') + options['name']
    headers = {'X-Vault-Token': current_app.config.get('VAULT_AUTH_TOKEN')}
    params = process_role_options(options)

    try:
        resp = requests.post(url, data=params, headers=headers)

        if resp.status_code != 204:
            raise Exception('Vault error' + resp.content)
        current_app.logger.info('Vaule PKI role created successfully.')
    except ConnectionError as ConnError:
        current_app.logger.info('Connection Error')
        raise ConnError


def get_ca_certificate():
    url = current_app.config.get('VAULT_CA_URL')

	try:
    	resp = requests.get(url)
		if resp.status_code != 200
			current_app.logger.info('Vault PKI failed to get CA Certificate.')
			raise Exception('Vault failed to get CA certificate.')

    	cert = resp.content[:-1]

	    return cert

	except ConnectionError as ConnError:
		current_app.logger.info('There was an error while connecting to Vault server.')
        raise ConnError


class VaultIssuerPlugin(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = lemur_vault.VERSION

    author = 'Ron Cohen'
    author_url = 'https://github.com/RcRonco/lemur_vault'

    def create_certificate(self, csr, issuer_options):
        headers = {'X-Vault-Token': current_app.config.get('VAULT_AUTH_TOKEN')}

        if csr:
            url = current_app.config.get('VAULT_SIGN_URL')
        else:
            url = current_app.config.get('VAULT_ISSUE_URL')

        url += issuer_options['authority'].name
        params = process_sign_options(issuer_options, csr)

        try:
            resp = requests.post(url, data=params, headers=headers)

            if resp.status_code != 200:
                current_app.logger.info('Vault certificate signing failed - Vault error code' + str(resp.status_code) + '.')
                raise Exception('Vault Error', resp.content)

            cert = resp.json()['data']['certificate']
            int_cert = resp.json()['data']['issuing_ca']

            if not cert:
                current_app.logger.info('Vault certificate signing failed.')
                raise Exception('Vault plugin error' + resp.content + '.')
            else:
                current_app.logger.info('Vault certificate created successfully.')
                return cert, int_cert

        except ConnectionError as ConnError:
            current_app.logger.info('There was an error while connecting to Vault server.')
            raise ConnError

    @staticmethod
    def create_authority(options):
        create_vault_role(options)
        cert = get_ca_certificate()
        role = {'username': '', 'password': '', 'name': 'vault'}

        current_app.logger.info('Vault CA created successfully.')
        return cert, "", [role]
