# Configure Vault as a Certificate Authority

#### This can be done in two ways:

**1. Vault generated CA.**

- Mount the PKI backend with this command:

  ```sh
  vault mount pki
  ```
  
- Now we set maximum life time for the certificate:

  ```sh
  vault mount-tune -max-lease-ttl=87600h pki
  ```
  
- We generate our root certificate:

  ```sh
  vault write pki/root/generate/internal common_name=myvault.com ttl=87600h
  ```

- Configure a role:
  
  ```sh
  vault write pki/roles/example-role allow_any_name="true" \
  allow_subdomains="true" allow_ip_sans="true" max_ttl="72h" \
  allow_localhost="true" allow_ip_sans="true"
  ```
 
WARNING: When running Vault in "Dev" Server Mode, Vault shutdown will result CA being deleted.
 
**2. Externally generated CA.**
- Mount the PKI backend with this command:

  ```sh
  vault mount pki
  ```
- Now we need to create a certificate bundle:

  ```sh
  export CA_PATH=/PATH/TO/CA
  cat $CA_PATH/ca.cert.pem > /path/to/vault/ca_bundle.pem
  openssl rsa -in $CA_PATH/private/ca.key >> /path/to/vault/ca_bundle.pem
  ```
  
- Assign CA to vault:

  ```sh
  vault write pki/config/ca pem_bundle="@/path/to/vault/ca_bundle.pem"
  ```

- Configure a role:
  
  ```sh
  vault write pki/roles/example-role allow_any_name="true" \
  allow_subdomains="true" allow_ip_sans="true" max_ttl="72h" \
  allow_localhost="true" allow_ip_sans="true"
  ```
