# Configure Vault as a Certificate Authority
- To mount the PKI mount in Vault enter the command:

  ```sh
  vault mount pki
  ```
- Now we need to create a certificate bundle:

  ```sh
  export CA_PATH=/PATH/TO/CA
  cat $CA_PATH/ca.cert.pem > /path/to/vault/ca_bundle.pem
  openssl rsa -in $CA_PATH/private/ca.key >> /path/to/vault/ca_bundle.pem
  ```
  
- Configure vault as CA:

  ```sh
  vault write pki/config/ca pem_bundle="@/path/to/vault/ca_bundle.pem"
  ```

- Configure a role:
  
  ```sh
  vault write pki/roles/example-role allow_any_name="true" \
  allow_subdomains="true" allow_ip_sans="true" max_ttl="72h" \
  allow_localhost="true" allow_ip_sans="true"
  ```
