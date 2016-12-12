import requests
import math

from lemur.plugins import lemur_vault
from lemur.plugins.bases.issuer import IssuerPlugin
from flask import current_app
from requests import ConnectionError


def handle_request(method, url, headers={}, data=''):
    try:
        if method == 'GET':
            resp = requests.get(url, headers=headers)
        elif method == 'POST':
            resp = requests.post(url, data=data, headers=headers)

        if resp.status_code != 200 or resp.status_code != 200:
            current_app.logger.info('Vault PKI failed to get CA Certificate.')
            return False, resp.json()['errors'][0]

        return True, resp

    except ConnectionError as ConnError:
        current_app.logger.info('There was an error while connecting to Vault server.')
        raise ConnError


def process_sign_options(options, csr):
    vault_params = '{"format":"pem", "common_name": "' + options['common_name'] + '"'

    if csr:
        vault_params += ', "csr": "' + csr.replace('\n', '\\n') + '"'

    alt_names = options['extensions']['sub_alt_names']['names']
    dns_names = ''
    ip_sans = ''

    for name in alt_names:
        if name['name_type'] == 'DNSName':
            dns_names += name['value'] + ', '
        if name['name_type'] == 'IPAddress':
            ip_sans += name['value'] + ', '

    if dns_names != '':
        vault_params += ', "alt_names": "' + dns_names[:-2] + '"'
    if ip_sans != '':
        vault_params += ', "ip_sans": "' + ip_sans[:-2] + '"'

    is_valid, ttl = validate_ttl(options)

    if is_valid:
        vault_params += ', "ttl": "' + str(int(ttl)) + 'h"'
    else:
        raise Exception('TTL is too high please choose date sooner.')

    vault_params += '}'

    return vault_params


def validate_ttl(options):
    if 'validity_end' in options and 'validity_start' in options:
        ttl = math.floor(abs(options['validity_end'] - options['validity_start']).total_seconds() / 3600)
    elif 'validity_years' in options:
        ttl = options['validity_years'] * 365 * 24

    headers = {'X-Vault-Token': current_app.config.get('VAULT_AUTH_TOKEN')}
    res, resp = handle_request('GET', current_app.config.get('VAULT_URL') + '/roles/' + options['authority'].name,
                               headers=headers)

    if res:
        max_ttl = resp.json()['data']['max_ttl']
        if int(max_ttl.rsplit('h', 1)[0]) < ttl:
            current_app.logger.info('Certificate TTL is above max ttl - ' + max_ttl)
            return False, -1
        else:
            return True, ttl
    else:
        raise Exception('Vault error' + resp.json()['errors'][0])


def process_role_options(options):
    vault_params = '{"allow_subdomains":"true", "allow_any_name":"true"'

    if 'key_type' in options:
        vault_params += ',"key_type":"' + options['key_type'][:3].lower() + '", "key_bits":"' + options['key_type'][
                                                                                                -4:] + '"'
    key_usage = ',"key_usage":"'

    if 'extensions' in options and 'key_usage' in options['extensions']:
        if 'use_digital_signature' in options['extensions']['key_usage']:
            key_usage += 'DigitalSignature,'
        if 'use_key_encipherment' in options['extensions']['key_usage']:
            key_usage += 'KeyEncipherment,'
        vault_params += key_usage + 'KeyAgreement"'

    ttl = -1

    if 'validity_end' in options and 'validity_start' in options:
        ttl = math.floor(abs(options['validity_end'] - options['validity_start']).total_seconds() / 3600)
    elif 'validity_years' in options:
        ttl = options['validity_years'] * 365 * 24

    if ttl > 0:
        vault_params += ',"ttl":"' + str(ttl) + 'h", "max_ttl":"' + str(ttl) + 'h"'

    vault_params += '}'

    return vault_params


def create_vault_role(options):
    url = current_app.config.get('VAULT_URL') + '/roles/' + options['name']
    headers = {'X-Vault-Token': current_app.config.get('VAULT_AUTH_TOKEN')}
    params = process_role_options(options)

    res, resp = handle_request('POST', url, params, headers)
    if res:
        current_app.logger.info('Vaule PKI role created successfully.')
    else:
        raise Exception('Vault error' + resp.json()['errors'][0])


def get_ca_certificate():
    url = current_app.config.get('VAULT_URL') + '/ca/pem'
    res, resp = handle_request('GET', url)

    if res:
        ca_cert = resp.content[:-1]
        return ca_cert
    else:
        current_app.logger.info('Vault PKI failed to get CA Certificate.')
        raise Exception('Vault failed to get CA certificate.')


def get_chain_certificate():
    url = current_app.config.get('VAULT_URL') + '/ca_chain'

    res, resp = handle_request('GET', url)
    if res:
        chain_cert = resp.content
    else:
        chain_cert = ''

    return chain_cert


class VaultIssuerPlugin(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = lemur_vault.VERSION

    author = 'Ron Cohen'
    author_url = 'https://github.com/RcRonco/lemur_vault'

    def create_certificate(self, csr, issuer_options):
        headers = {'X-Vault-Token': current_app.config.get('VAULT_AUTH_TOKEN')}

        if type(csr) is bytes:
            csr = csr.decode('utf-8')

        if csr:
            url = current_app.config.get('VAULT_URL') + '/sign/'
        else:
            url = current_app.config.get('VAULT_URL') + '/issue/'

        url += issuer_options['authority'].name
        params = process_sign_options(issuer_options, csr)

        res, resp = handle_request('POST', url, headers, params)

        if not res:
            current_app.logger.info(
                'Vault certificate signing failed - Vault error code' + str(resp.status_code) + '.')
            raise Exception('Vault error' + resp.json()['errors'][0])
        else:
            json_resp = resp.json()
            cert = json_resp['data']['certificate']

            if 'ca_chain' in json_resp['data']:
                chain_certs = json_resp['data']['ca_chain']
                int_cert = '\n'.join(chain_certs)
            else:
                int_cert = json_resp['data']['issuing_ca']

            if not cert:
                current_app.logger.info('Vault certificate signing failed.')
                raise Exception('Vault plugin error' + resp.content + '.')
            else:
                current_app.logger.info('Vault certificate created successfully.')
                return cert, int_cert


    @staticmethod
    def create_authority(options):
        ca_cert = get_ca_certificate()
        chain_cert = get_chain_certificate()
        create_vault_role(options)

        role = {'username': '', 'password': '', 'name': 'vault'}
        current_app.logger.info('Vault CA created successfully.')

        if type(ca_cert) is bytes:
            ca_cert = ca_cert.decode('utf-8')
        if type(chain_cert) is bytes:
            chain_cert = chain_cert.decode('utf-8')

        return ca_cert, chain_cert, [role]
