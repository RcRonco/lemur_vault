# Vault plugin
[Hashicorp Vault](https://github.com/hashicorp/vault) plugin for [Netflix Lemur](https://github.com/Netflix/lemur).

## Prerequisites
1. Lemur 0.3+
2. Hashicorp Vault with PKI backend mounted.

## Installation
1. Configure the Vault PKI as Certificate Authority.
2. To install the plugin, add the following lines to your lemur.conf.py file:    

  ```python
  # Hashicorp Vault Plugin
  VAULT_BASE_URL = 'http://127.0.0.1:8200' # as example
  VAULT_AUTH_TOKEN = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
  VAULT_CA_URL = VAULT_BASE_URL + '/v1/pki/ca/pem'
  VAULT_ISSUE_URL = VAULT_BASE_URL + '/v1/pki/issue/'
  VAULT_SIGN_URL = VAULT_BASE_URL + '/v1/pki/sign/'
  ```

3. Deploy and install the files.
4. Create a Certificate Authority in the lemur web interface.

## Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D
