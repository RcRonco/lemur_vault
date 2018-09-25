import requests
import math
import json

from flask import current_app
from requests import ConnectionError
from lemur.plugins.bases.issuer import IssuerPlugin
from lemur.plugins.lemur_vault import auth as vault_auth, VERSION as VAULT_PLUGIN_VER


def vault_write_request(url, data):
    """
    This is a write request function to vault.
    :param url: url to the Vault server
    :param data: json string with all Vault parameters
    :return: 1. Boolean if the request succeed or not.
             2. If succeed return response object if failed return error string.
    """
    headers = {'X-Vault-Token': vault_auth.get_token()}
    try:
        if url.split('//')[0].lower() == 'https:':
            verify = current_app.config.get('VAULT_CA')
        else:
            verify = ''

        resp = requests.post(url, data=data, headers=headers, verify=verify)

        if resp.status_code != 200 and resp.status_code != 204:
            current_app.logger.info('Vault: ' + resp.json()['errors'][0])
            return False, resp.json()['errors'][0]

        return True, resp

    except ConnectionError as ConnError:
        current_app.logger.info('Vault: There was an error while connecting to Vault server.')
        raise ConnError


def vault_read_request(url, headers=None):
    """
    This is a read request function to vault.
    :param url: url to the Vault server
    :param headers: headers for the GET request
    :return: 1. Boolean if the request succeed or not.
             2. If succeed return response object if failed return error string.
    """
    try:
        if url.split('//')[0].lower() == 'https:':
            verify = current_app.config.get('VAULT_CA')
        else:
            verify = ''

        if headers:
            resp = requests.get(url, headers=headers, verify=verify)
        else:
            resp = requests.get(url, verify=verify)

        if resp.status_code != 200 and resp.status_code != 204:
            current_app.logger.info('Vault: ' + resp.json()['errors'][0])
            return False, resp.json()['errors'][0]

        return True, resp

    except ConnectionError as ConnError:
        current_app.logger.info('Vault: There was an error while connecting to Vault server.')
        raise ConnError


def process_sign_options(options, csr):
    """
    Parse Lemur options and convert them to Vault parameter in json format.
    :param options: Lemur option dictionary
    :param csr: CSR
    :return: All needed parameters for Vault signing endpoint in json formatted string.
    """
    vault_params = {'format': 'pem', 'common_name': options['common_name']}

    if csr:
        vault_params['csr'] = csr

    alt_names = options['extensions']['sub_alt_names']['names']
    dns_names = ''
    ip_sans = ''

    for name in alt_names:
        if name == 'DNSName':
            dns_names += name.value + ', '
        if name == 'IPAddress':
            ip_sans += name.value + ', '

    if dns_names != '':
        vault_params['alt_names'] = dns_names[:-2]
    if ip_sans != '':
        vault_params['ip_sans'] = ip_sans[:-2]

    is_valid, ttl = validate_ttl(options)

    if is_valid:
        vault_params['ttl'] = str(int(ttl)) + 'h'
    else:
        raise Exception('Vault: TTL is too high please choose date sooner.')

    return json.dumps(vault_params)


def validate_ttl(options):
    """
    Check with Vault if the ttl is valid.
    :param options: Lemur option dictionary
    :return: 1. Boolean if the ttl is valid or not.
             2. the ttl in hours.
    """
    if 'validity_end' in options and 'validity_start' in options:
        ttl = math.floor(abs(options['validity_end'] - options['validity_start']).total_seconds() / 3600)
    elif 'validity_years' in options:
        ttl = options['validity_years'] * 365 * 24
    else:
        ttl = 0

    headers = {'X-Vault-Token': vault_auth.get_token()}
    url = '{}/roles/{}'.format(current_app.config.get('VAULT_PKI_URL'), options['authority'].name)
    res, resp = vault_read_request(url, headers)

    if res:
        max_ttl = resp.json()['data']['max_ttl']
        if int(max_ttl.rsplit('h', 1)[0]) < ttl:
            current_app.logger.info('Certificate TTL is above max ttl - ' + max_ttl)
            return False, -1
        else:
            return True, ttl
    else:
        current_app.logger.info('Vault: Failed to get Vault max TTL')
        raise Exception('Vault: ' + resp)


def process_role_options(options):
    """
    Parse Lemur options and convert them to Vault parameter in json format.
    :param options: Lemur option dictionary
    :return: All needed parameters for Vault roles endpoint in json formatted string.
    """
    vault_params = {'allow_subdomains': 'true', 'allow_any_name': 'true'}

    if 'key_type' in options:
        vault_params['key_type'] = options['key_type'][:3].lower()
        vault_params['key_bits'] = options['key_type'][-4:]

    vault_params['key_usage'] = 'KeyAgreement'
    if 'extensions' in options and 'key_usage' in options['extensions']:
        if options['extensions']['key_usage'].digital_signature:
            vault_params['key_usage'] += ', DigitalSignature'
        if options['extensions']['key_usage'].key_encipherment:
            vault_params['key_usage'] += ', KeyEncipherment'

    ttl = -1

    if 'validity_end' in options and 'validity_start' in options:
        ttl = math.floor(abs(options['validity_end'] - options['validity_start']).total_seconds() / 3600)
    elif 'validity_years' in options:
        ttl = options['validity_years'] * 365 * 24

    if ttl > 0:
        vault_params['ttl'] = str(ttl) + 'h'
        vault_params['max_ttl'] = str(ttl) + 'h'

    return json.dumps(vault_params)


def create_vault_role(options):
    """
    Create a role in Vault the matches the Lemur CA options.
    :param options: Lemur option dictionary
    """
    url = '{}/roles/{}'.format(current_app.config.get('VAULT_PKI_URL'), options['name'])
    params = process_role_options(options)

    res, resp = vault_write_request(url, params)

    if res:
        current_app.logger.info('Vaule PKI role created successfully.')
    else:
        current_app.logger.info('Vaule PKI Failed to create role.')
        raise Exception('Vault error' + resp)


def get_ca_certificate():
    """
    Get from Vault the CA certificate
    :return: A CA certificate string in PEM format.
    """
    url = current_app.config.get('VAULT_PKI_URL') + '/ca/pem'
    res, resp = vault_read_request(url)

    if res:
        ca_cert = resp.content[:-1]
        return ca_cert
    else:
        current_app.logger.info('Vault PKI failed to get CA Certificate.')
        raise Exception('Vault failed to get CA certificate.')


def get_chain_certificate():
    """
    Get from Vault the CA chain certificates
    :return: A CA chain certificates string in PEM format.
    """
    url = current_app.config.get('VAULT_PKI_URL') + '/ca_chain'
    res, resp = vault_read_request(url)

    if res:
        chain_cert = resp.content
    else:
        chain_cert = ''

    return chain_cert


class VaultIssuerPlugin(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = VAULT_PLUGIN_VER

    author = 'Ron Cohen'
    author_url = 'https://github.com/RcRonco/lemur_vault'

    def create_certificate(self, csr, issuer_options):
        if type(csr) is bytes:
            csr = csr.decode('utf-8')

        if csr:
            url = current_app.config.get('VAULT_PKI_URL') + '/sign/'
        else:
            url = current_app.config.get('VAULT_PKI_URL') + '/issue/'

        url += issuer_options['authority'].name
        params = process_sign_options(issuer_options, csr)
        res, resp = vault_write_request(url, params)

        if not res:
            current_app.logger.info('Vault: ' + resp + '.')
            raise Exception('Vault: ' + resp)
        else:
            json_resp = resp.json()
            cert = json_resp['data']['certificate']
            external_id = json_resp['request_id']

            if 'ca_chain' in json_resp['data']:
                chain_certs = json_resp['data']['ca_chain']
                int_cert = '\n'.join(chain_certs)
            else:
                int_cert = json_resp['data']['issuing_ca']

            if not cert:
                current_app.logger.info('Vault certificate signing failed.')
                raise Exception('Vault: ' + resp.content + '.')
            else:
                current_app.logger.info('Vault: certificate created successfully.')
                return cert, int_cert, external_id

    @staticmethod
    def create_authority(options):
        ca_cert = get_ca_certificate()
        chain_cert = get_chain_certificate()
        create_vault_role(options)

        role = {'username': '', 'password': '', 'name': 'Vault'}
        current_app.logger.info('Vault: CA created successfully.')

        if type(ca_cert) is bytes:
            ca_cert = ca_cert.decode('utf-8')
        if type(chain_cert) is bytes:
            chain_cert = chain_cert.decode('utf-8')

        return ca_cert, chain_cert, [role]
