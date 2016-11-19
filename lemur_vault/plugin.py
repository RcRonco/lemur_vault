import requests

import lemur_vault
from lemur.plugins.bases.issuer import IssuerPlugin
from flask import current_app

def process_options(options):
    data = '{"format":"pem", "common_name": "' + options['common_name'] + '"'

    alt_names = options['extensions']['sub_alt_names']['names']
    dnsnames = ''
    ipsans = ''

    for name in alt_names:
        if name['name_type'] == 'DNSName':
            dnsnames += name['value'] + ', '
        if name['name_type'] == 'IPAddress':
            ipsans += name['value'] + ', '

    if dnsnames != '':
        data += ', "alt_names": "' + dnsnames[:-2] + '"'
    if ipsans != '':
        data += ', "ip_sans": "' + ipsans[:-2] + '"'

    data += '}'
    return data

def get_ca_certificate():
    url = current_app.config.get('VAULT_CA_URL')
    resp = requests.get(url)

    cert = resp.content[:-1]
    return cert


class VaultIssuerPlugin(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = lemur_vault.VERSION

    author = 'Ron Cohen'
    author_url = 'https://github.com/RcRonco/vault_plugin'

    def create_certificate(self, csr, issuer_options):
        headers = {'X-Vault-Token': current_app.config.get('VAULT_AUTH_TOKEN')}
        url = current_app.config.get('VAULT_ISSUE_URL') + 'web-server'

        params = process_options(issuer_options)
        resp = requests.put(url, data=params, headers=headers)

        print(resp.content)
        print(resp.status_code)

        if resp.status_code != 200:
            raise Exception('Vault Error', resp.content)

        cert = resp.json()['data']['certificate']
        int_cert = get_ca_certificate()
        if not cert:
            raise Exception("error")
        else:
            return cert, int_cert

    @staticmethod
    def create_authority(options):
        role = {'username': '', 'password': '', 'name': 'vault'}
        cert = get_ca_certificate()
        return cert, "", [role]