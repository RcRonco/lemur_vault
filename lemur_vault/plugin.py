import requests
import math
import json
import OpenSSL

import lemur_vault
from lemur.plugins.bases.issuer import IssuerPlugin
from flask import current_app
from requests import ConnectionError

vault_token = None


def vault_write_request(url, data):
    """
    This is a write request function to vault.
    :param url: url to the Vault server
    :param data: json string with all Vault parameters
    :return: 1. Boolean if the request succeed or not.
             2. If succeed return response object if failed return error string.
    """
    headers = {'X-Vault-Token': get_token()}
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

    headers = {'X-Vault-Token': get_token()}
    res, resp = vault_read_request(current_app.config.get('VAULT_PKI_URL') + '/roles/' + options['authority'].name,
                                   headers)

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
    url = current_app.config.get('VAULT_PKI_URL') + '/roles/' + options['name']
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


def get_token():
    """
    Get token from Vault.
    :return: A CA chain certificates string in PEM format.
    """
    vault_token = None

    if vault_token is None:
        auth_type = current_app.config.get('VAULT_AUTH')
        if auth_type == 'TOKEN':
            vault_token = current_app.config.get('VAULT_AUTH_TOKEN')
        elif auth_type == 'USERPASS':
            vault_token = authenticate_userpass()
        elif auth_type == 'CERT':
            vault_token = authenticate_certificate()
        elif auth_type == 'GCP':
            vault_token = authenticate_gcp()
        else:
            current_app.logger.info('Vault: VAULT_AUTH not configured correctly.')
            raise Exception('Vault: VAULT_AUTH not configured correctly.')

    return vault_token



def authenticate_userpass():
    """
    User and password authentication function.
    :return: Client token.
    """
    if current_app.config.get('VAULT_AUTH_USERNAME') and current_app.config.get('VAULT_AUTH_PASSWORD'):
        url = current_app.config.get('VAULT_URL') + '/auth/userpass/login/' + current_app.config.get(
            'VAULT_AUTH_USERNAME')
        try:
            if url.split('//')[0].lower() == 'https:':
                verify = current_app.config.get('VAULT_CA')
            else:
                verify = ''

            data = '{ "password": "' + current_app.config.get('VAULT_AUTH_PASSWORD') + '" }'
            resp = requests.post(url, data=data, verify=verify)

            if resp.status_code != 200 and resp.status_code != 204:
                current_app.logger.info('Vault: ' + resp.json()['errors'][0])
                return resp.json()['errors'][0]

            return resp.json()['auth']['client_token']

        except ConnectionError as ConnError:
            current_app.logger.info('Vault: There was an error while connecting to Vault server.')
            raise ConnError
    else:
        raise Exception('Vault Config: Username or password not set.')


def authenticate_certificate():
    """
    Certificate authentication function.
    :return: Client token.
    """
    certificate = current_app.config.get('VAULT_AUTH_CERT')
    certkey = current_app.config.get('VAULT_AUTH_CERTKEY')

    if certificate and certkey:
        try:
            if current_app.config.get('VAULT_URL') + '/auth/cert/login'.split('//')[0].lower() != 'https:':
                raise Exception('Vault: Certificate authentication work only in https!')

            verify = current_app.config.get('VAULT_CA')
            resp = requests.post(current_app.config.get('VAULT_URL') + '/auth/cert/login', cert=(certificate, certkey),
                                 verify=verify)

            if resp.status_code != 200 and resp.status_code != 204:
                current_app.logger.info('Vault: ' + resp.json()['errors'][0])
                return resp.json()['errors'][0]

            return resp.json()['auth']['client_token']

        except ConnectionError as ConnError:
            current_app.logger.info('Vault: There was an error while connecting to Vault server.')
            raise ConnError
        except OpenSSL.SSL.Error:
            raise Exception('Vault: error occurred while accessing the certificate files, please check the path.')
    else:
        raise Exception('Vault Config: cert or key path not set.')


def generate_gcp_jwt():
    """
    Generate GCP JWT for Vault authentication.
    :return: GCP JWT
    """
    role = current_app.config.get('VAULT_AUTH_ROLE')
    account = current_app.config.get('VAULT_AUTH_ACCOUNT')

    if role and account:
        headers = {'Metadata-Flavor': 'Google'}
        url = 'http://metadata/computeMetadata/v1/instance/service-accounts/' + account + '/identity'
        try:
            data = [('audience', current_app.config.get('VAULT_URL') + '/vault/' + role ),('format', 'full')]
            resp = requests.post(url, headers=headers, data=data)
            
            if resp.status_code != 200 and resp.status_code != 204:
                current_app.logger.info('Vault: ' + resp.text)
                raise Exception('Vault GCP Auth: Issues retrieving JWT.')

            return resp.text

        except ConnectionError as ConnError:
            current_app.logger.info('Vault: There was an error while connecting to GCE metadata.')
            raise ConnError

    else:
        raise Exception('Vault Config: Role and Service Account not set.')



def authenticate_gcp():
    """
    GCP JWT authentication function.
    :return: Client token.
    """"
    role = current_app.config.get('VAULT_AUTH_ROLE')

    if role:
        url = current_app.config.get('VAULT_URL') + '/v1/auth/gcp/login'
        try:
            if url.split('//')[0].lower() == 'https:':
                verify = current_app.config.get('VAULT_CA')
            else:
                verify = ''
            jwt = generate_gcp_jwt()
            json = {"role": '{}'.format(role), "jwt": '{}'.format(jwt)}
            resp = requests.post(url, json=json, verify=verify)
                                    
            if resp.status_code != 200 and resp.status_code != 204:
                current_app.logger.info('Vault: ' + response.json()['errors'][0]
                return resp.json()['errors'][0]
                                        
            return resp.json()['auth']['client_token']
                                        
        except ConnectionError as ConnError:
            current_app.logger.info('Vault: There was an error while connecting to Vault server.')
            raise ConnError
                                        
    else:
        raise Exception('Vault Config: Vault Role not set.')



class VaultIssuerPlugin(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = lemur_vault.VERSION

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
