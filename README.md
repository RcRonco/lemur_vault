# Vault plugin
[Hashicorp Vault](https://github.com/hashicorp/vault) plugin for [Netflix Lemur](https://github.com/Netflix/lemur).

## Prerequisites
1. Lemur 0.6.0
2. Hashicorp Vault 0.6.2 and above.

## Installation
1. Configure the [Vault PKI as Certificate Authority](Vault_CA.md).
2. To install the plugin, add the needed options to your lemur.conf.py file:

  ```python
  # Hashicorp Vault Plugin
  # Basic options:
  (REQUIRED) VAULT_URL = 'http://myvault.com:8200/v1'
  (REQUIRED) VAULT_PKI_URL = VAULT_URL + '/pki'

  # For HTTPS add the path to the certificate chain.
  (OPTIONAL) VAULT_CA = '/path/ca/certificate'

  # Authentication options:
  (REQUIRED) VAULT_AUTH = 'TOKEN' | 'USERPASS' | 'CERT'
  VAULT_AUTH_TOKEN = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' # for token auth
  VAULT_AUTH_USERNAME = 'myvaultuser' # for userpass auth
  VAULT_AUTH_PASSWORD = 'Vault123'  # for userpass auth
  VAULT_AUTH_CERT = '/tmp/crt.pem # for certificate auth
  VAULT_AUTH_CERTKEY = '/tmp/key.pem # for certificate auth
   ```

3. Deploy and install the files.

  ```sh
  # Install Vault Plugin
  cd lemur/plugins/
  git clone https://github.com/RcRonco/lemur_vault
  cd lemur_vault
  pip install .
  ```
  
4. Create a Certificate Authority in the lemur web interface.

## Contributing
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D
