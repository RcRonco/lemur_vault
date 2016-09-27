import vault_plugin
import requests

from lemur.plugins.base.issuer import IssuerPlugin

def process_options(options)
    data['format'] = 'pem'
    return data

class PluginName(IssuerPlugin):
    title = 'Hashicorp Vault'
    slug = 'HashicorpVault'
    description = 'A plugin for hashicorp Vault secret management software.'
    version = vault_plugin.VERSION

    author = 'Ron Cohen'
    author_url = 'https://github.com/RcRonco/vault_plugin'

    VAULT_URL = 'https://vault.mydomain.com:8200/pki/sign/cert_role'

   def create_certificate(self, csr, options):
       post_params = process_options(options)
       post_params['csr'] = csr
       resp = requests.post(VAULT_URL, post_params)
       if resp.status_code != 200:
            raise ApiError('POST /pki/sign/ '.format(resp.status_code))

     @staticmethod
    def create_authority(options):
        raise NotImplemented

       