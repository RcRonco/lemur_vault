import OpenSSL
import requests
import datetime
from flask import current_app

vault_token = None
vault_token_time = None


def validate_token():
    """
    Check that the saved token is valid
    :return: Return true if the token is set and still valid
    """
    global vault_token
    global vault_token_time

    if vault_token is None:
        return False

    return datetime.datetime.now() < vault_token_time


def get_token():
    """
    Get token from Vault.
    :return: A valid Vault token
    """
    global vault_token
    global vault_token_time

    if validate_token():
        vault_duration = None
        try:
            auth_type = current_app.config.get('VAULT_AUTH', 'TOKEN')
            if auth_type == 'TOKEN':
                vault_token = current_app.config.get('VAULT_AUTH_TOKEN')
            elif auth_type == 'USERPASS':
                vault_token, vault_duration = authenticate_userpass()
            elif auth_type == 'LDAP':
                vault_token, vault_duration = authenticate_ldap()
            elif auth_type == 'CERT':
                vault_token, vault_duration = authenticate_certificate()
            elif auth_type == 'GCP':
                vault_token, vault_duration = authenticate_gcp()
            elif auth_type == 'APPROLE':
                vault_token, vault_duration = authenticate_approle()
            else:
                current_app.logger.info('Vault: VAULT_AUTH not configured correctly.')
                raise RuntimeError('Vault: VAULT_AUTH not configured correctly.')
            if vault_duration is not None:
                vault_token_time = datetime.datetime.now() + datetime.timedelta(seconds=int(vault_duration))

        except ConnectionError as ConnError:
            current_app.logger.info('Vault: There was an error while connecting to Vault server.')
            raise ConnError

    return vault_token


def _userpwd_auth(vault_auth_path):
    """
    User and password authentication function.
    :param vault_auth_path: Authentication mount path
    :return:  Client token and lease duration
    """
    if current_app.config.get('VAULT_AUTH_USERNAME') and current_app.config.get('VAULT_AUTH_PASSWORD'):
        url = '{}/v1/auth/{}/login/{}'.format(current_app.config.get('VAULT_URL'),
                                              vault_auth_path,
                                              current_app.config.get('VAULT_AUTH_USERNAME'))

        if url.split('//')[0].lower() == 'https:':
            verify = current_app.config.get('VAULT_CA')
        else:
            verify = ''

        json = {'password': '{}'.format(current_app.config.get('VAULT_AUTH_PASSWORD'))}
        resp = requests.post(url, json=json, verify=verify)

        if resp.status_code != 200 and resp.status_code != 204:
            current_app.logger.info('Vault: ' + resp.json()['errors'][0])
            return resp.json()['errors'][0], None

        return resp.json()['auth']['client_token'], resp.json()['auth']['lease_duration']
    else:
        raise RuntimeError('Vault Config: Username or password not set.')


def authenticate_ldap():
    """
    Authenticate with user and password, default auth path is LDAP
    :return:  Client token and lease duration
    """
    return _userpwd_auth(current_app.config.get('VAULT_AUTH_PATH', 'ldap'))


def authenticate_userpass():
    """
    Authenticate with user and password, default auth path is LDAP
    :return:  Client token and lease duration
    """
    return _userpwd_auth(current_app.config.get('VAULT_AUTH_PATH', 'userpass'))


def authenticate_certificate():
    """
    Certificate authentication function.
    :return:  Client token and lease duration
    """
    certificate = current_app.config.get('VAULT_AUTH_CERT')
    certkey = current_app.config.get('VAULT_AUTH_CERTKEY')

    if certificate and certkey:
        try:
            if current_app.config.get('VAULT_URL').split('//')[0].lower() != 'https:':
                raise RuntimeError('Vault: Certificate authentication work only in https!')

            verify = current_app.config.get('VAULT_CA')
            url = '{}/v1/auth/{}/login'.format(current_app.config.get('VAULT_URL'),
                                               current_app.config.get('VAULT_AUTH_PATH', 'cert'))
            resp = requests.post(url, cert=(certificate, certkey), verify=verify)

            if resp.status_code != 200 and resp.status_code != 204:
                current_app.logger.info('Vault: ' + resp.json()['errors'][0])
                return resp.json()['errors'][0], None

            return resp.json()['auth']['client_token'], resp.json()['auth']['lease_duration']

        except OpenSSL.SSL.Error:
            raise RuntimeError('Vault: error occurred while accessing the certificate files, please check the path.')
    else:
        raise RuntimeError('Vault Config: cert or key path not set.')


def authenticate_approle():
    """
    AppRole authentication function
    :return:  Client token and lease duration
    """
    role = current_app.config.get('VAULT_AUTH_ROLE')
    secret = current_app.config.get('VAULT_AUTH_SECRET')

    if role and secret:
        url = '{}/v1/auth/{}/login'.format(current_app.config.get('VAULT_URL'),
                                           current_app.config.get('VAULT_AUTH_PATH', 'approle'))
        if url.split('//')[0].lower() == 'https:':
            verify = current_app.config.get('VAULT_CA')
        else:
            verify = ''

        json = {"role_id": role, "secret_id": secret}
        resp = requests.post(url, json=json, verify=verify)

        if resp.status_code != 200 and resp.status_code != 204:
            current_app.logger.info('Vault: ' + resp.json()['errors'][0])
            return resp.json()['errors'][0], None

        return resp.json()['auth']['client_token'], resp.json()['lease_duration']
    else:
        raise RuntimeError('Vault Config: role id or secret id or both not set.')


def _generate_gcp_jwt():
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
            data = [('audience', current_app.config.get('VAULT_URL') + '/vault/' + role), ('format', 'full')]
            resp = requests.post(url, headers=headers, data=data)

            if resp.status_code != 200 and resp.status_code != 204:
                current_app.logger.info('Vault: ' + resp.text)
                raise Exception('Vault GCP Auth: Issues retrieving JWT.')

            return resp.text

        except ConnectionError as ConnError:
            current_app.logger.info('Vault: There was an error while connecting to GCE metadata.')
            raise RuntimeError('Vault: There was an error while connecting to GCE metadata.\n{}'.format(ConnError))

    else:
        raise RuntimeError('Vault Config: Role and Service Account not set.')


def authenticate_gcp():
    """
    GCP JWT authentication function.
    :return: Client token.
    """
    role = current_app.config.get('VAULT_AUTH_ROLE')

    if role:
        url = '{}/v1/auth/{}/login'.format(current_app.config.get('VAULT_URL'),
                                           current_app.config.get('VAULT_AUTH_PATH', 'gcp'))
        if url.split('//')[0].lower() == 'https:':
            verify = current_app.config.get('VAULT_CA')
        else:
            verify = ''

        jwt = _generate_gcp_jwt()
        json = {"role": '{}'.format(role), "jwt": '{}'.format(jwt)}
        resp = requests.post(url, json=json, verify=verify)

        if resp.status_code != 200 and resp.status_code != 204:
            current_app.logger.info('Vault: ' + resp.json()['errors'][0])
            return resp.json()['errors'][0], None

        return resp.json()['auth']['client_token'], resp.json()['lease_duration']

    else:
        raise RuntimeError('Vault Config: Vault Role not set.')