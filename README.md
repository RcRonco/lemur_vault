# Vault plugin
[Hashicorp Vault](https://github.com/hashicorp/vault) plugin for [Netflix Lemur](https://github.com/Netflix/lemur).

## Prerequisites
1. Lemur 0.3+
2. Hashicorp Vault 0.6+ - 0.6.2 is the recommended version.

## Installation
1. Configure the [Vault PKI as Certificate Authority](Vault_CA.md).
2. To install the plugin, add the following lines to your lemur.conf.py file:    

  ```python
  # Hashicorp Vault Plugin
  VAULT_URL = 'http://127.0.0.1:8200/v1/pki' # as example
  VAULT_AUTH_TOKEN = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
  
  # For HTTPS add this option:
  VAULT_CA = '/path/ca/certificate' # path to the ca certificate sign the Vault https cert.
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
