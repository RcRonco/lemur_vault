import vault_plugin
import requests

from lemur.plugins.bases.issuer import IssuerPlugin
VAULT_ISSUE_PATH = '/v1/pki/issue/cert_role'


def process_options(options):
    data = '{"format":"pem", "common_name": "' + options['common_name'] + '"'
    if options['alt_names']:
        data += ', "alt_names": "' + options['alt_names'] + '"'
    if options['ip_sans']:
        data += ', "ip_sans": "' + options['ip_sans'] + '"'
    data += '}'
    return data


class PluginName(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = vault_plugin.VERSION

    author = 'Ron Cohen'
    author_url = 'https://github.com/RcRonco/vault_plugin'

    options = [
        {
            'name': 'VaultURL',
            'type': 'str',
            'required': True,
            'validation': '@(https?|http)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$@iS',
            'helpMessage': 'Must be a valid Vault server URL!',
        },
        {
            'name': 'VaultAuthToken',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid Kubernetes server Token!',
        },
    ]

    def create_certificate(self, options):
        headers = {'X-Vault-Token': self.get_option('VaultAuthToken', self.options)}
        url = self.get_option('VaultURL', self.options) + VAULT_ISSUE_PATH
        params = process_options(options)
        resp = requests.put(url, data=params, headers=headers)
        if resp.status_code != 200:
            raise Exception('vault_error', resp.status_code)

        cert = resp.json['data']['certificate']

        if not cert:
            return cert
        else:
            raise Exception("error")

    @staticmethod
    def create_authority(options):
        raise NotImplemented
