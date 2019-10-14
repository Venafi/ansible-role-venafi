Venafi Role for Ansible
=======================

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>

This solution implements an Ansible Role that uses the [VCert-Python](https://github.com/Venafi/vcert-python)
library to simplify certificate enrollment and ensure compliance with
enterprise security policy.  

Requirements
------------

Install VCert-Python using pip:  
`pip install vcert`

Quickstart
------------
1. Install Ansible and VCert via pip  
    `sudo pip install ansible vcert --upgrade` 

1. Prepare demo environment (if you want to use your own environment 
you can skip this step. Change tests/inventory file to use your own inventory.)  

    1. To run our test/demo playbook you'll need the Docker provisioning role.
    Download it into the tests/roles/provision_docker directory: 
        ```bash
        git clone https://github.com/chrismeyersfsu/provision_docker.git tests/roles/provision_docker
        ```
        
    1. Build Docker images needed for the demo playbook:
       ```bash
       docker build ./tests --tag local-ansible-test
       ```
    
    Demo certificates will be placed in the /tmp/ansible/etc/ssl directory on the Ansible host.
    From there they will be distributed to the /etc/ssl/ directory of remote hosts.
    
1. Generate a credentials file for either Venafi Platform or Venafi Cloud.  
    
    1. For Venafi Platform create a `credentials.yml` similar to the following:  
       ```yaml
       user: 'admin'
       password: 'myStrongTPP-Password'
       url: 'https://tpp.venafi.example/vedsdk/'
       zone: "example\\policy"
       trust_bundle: "/path-to/tpp-trust-bundle.pem"
       ```  
    1. For Venafi Cloud set the token to your API key in the credentials.yml and the Zone ID
    of the Venafi Cloud zone that you want to request certificates from:
       ```yaml
       token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx"
       zone: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx"
       ```
    1. Encrypt the credentials file using ansible-vault; you will be asked to enter a password:
       ```bash
       ansible-vault encrypt credentials.yml
       ```
    
1. Run Ansible playbook (remove docker_demo=true if you want to use your own inventory).
Choice between Cloud and Platform depends on credentials provided. If you set a token, the
playbook runs using Venafi Cloud. If you set a password, the playbook runs using Venafi Platform. 
You will be asked for the vault password you entered before.
    ```bash
    ansible-playbook -i tests/inventory \
     tests/venafi-playbook-example.yml \
     --extra-vars "credentials_file=credentials.yml docker_demo=true" \
     --ask-vault-pass
    ```

Using with Ansible Galaxy
--------------------------

1. Install role with Ansible Galaxy command:
    `ansible-galaxy install venafi.ansible_role_venafi` 

1. Generate credentials.yml as described in Quickstart

1. Write a simple playbook:
    ```yaml
    - hosts: localhost
      roles:
        - role: venafi.ansible_role_venafi
          certificate_cert_dir: "/tmp/etc/ssl/{{ certificate_common_name }}"
    ```

1. Run the playbook:
    `ansible-playbook vcert.yml --ask-vault-pass`
    It will generate a certificate and place it into folder in /tmp/etc/ssl/ directory. 
    You can change other parameters by changin more variables described bellow. Also look into variables in
    defaults/main.yml file. 

For more information about Ansible Galaxy, please refer to official documentation: 
https://galaxy.ansible.com/docs/using/installing.html    

Role Variables
--------------

For default variables values, please look into defaults/main.yml file.

```yaml
# Credentials.
venafi:
  # Venafi Platform connection parameters
  user: 'admin'
  password: 'myTPPpassword'
  url: 'https://tpp.venafi.example/vedsdk'
  zone: "devops\\vcert"
  # Path to the trust bundle for Venafi Platform server
  trust_bundle: "/opt/venafi/bundle.pem"
  # Venafi Cloud connection parameters
  #token: 'enter-cloud-api-token-here'
  #zone: 'enter Zone ID obtained from Venafi Cloud Web UI'
  #Test mode parameter
  #test_mode: true
  
# All variables from venafi section should be in credentials file.
credentials_file: credentials.yml

# Certificate parameters. These are examples.
certificate_common_name: "{{ ansible_fqdn }}"
certificate_alt_name: "IP:192.168.1.1,DNS:www.venafi.example.com,DNS:m.venafi.example.com,email:e@venafi.com,email:e2@venafi.com,IP Address:192.168.2.2"

certificate_privatekey_type: "RSA"
certificate_privatekey_size: "2048"
certificate_privatekey_curve: "P251"
certificate_privatekey_passphrase: "password"
certificate_chain_option: "last"

certificate_cert_dir: "/etc/ssl/{{ certificate_common_name }}"
certificate_cert_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"
certificate_chain_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"
certificate_privatekey_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"
certificate_csr_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.csr"

# Where to execute venafi_certificate module. If set to false, certificate will be
# created on Ansible master host and then copied to the remote server.
certificate_remote_execution: false
# Remote location where to place the certificate.
certificate_remote_cert_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"
certificate_remote_chain_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"
certificate_remote_privatekey_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"
# Set to false if you don't want to copy private key to remote location.
certificate_copy_private_key_to_remote: true

```



Dependencies
------------

vcert, ansible

```
sudo pip install ansible vcert --upgrade
```

Example Playbook
----------------

Playbook file example:  

```yaml
- hosts: servers
  roles:
    - role: "ansible-role-venafi"
      certificate_common_name: "{{ ansible_fqdn }}.venafi.example.com"
      certificate_cert_dir: "/tmp/ansible/etc/ssl/{{ certificate_common_name }}"
      certificate_cert_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"
      certificate_chain_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"
      certificate_privatekey_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"
      certificate_csr_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.csr"

      # Where to execute venafi_certificate module. If set to false, certificate will be
      # created on ansible master host and then copied to the remote server.
      certificate_remote_execution: false
      # Remote location where to place the certificate.
      certificate_remote_cert_dir: "/etc/ssl"
      certificate_remote_cert_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.pem"
      certificate_remote_chain_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.chain.pem"
      certificate_remote_privatekey_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.key"
      # Set to false if you don't want to copy private key to remote location.
      certificate_copy_private_key_to_remote: true

```

Credential file examples:  

for Venafi Platform:

```yaml
user: 'admin'
password: 'secret'
url: 'https://tpp.venafi.example/vedsdk/'
zone: "some\\policy"

```

for Venafi Cloud:  

```yaml
token: "xxxxx-xxxxx-xxxxx-xxxx-xxxxx"
zone: "xxxxx-xxxxx-xxxxx-xxxx-xxxxx"
```

By default credentials are read from file credentials.yml but can be overridden using 
the *credentials_file* variable, for example:  

    ansible-playbook playbook.yml --extra-vars "credentials_file=other_credentials.yml"

Look in the [/tests](/tests) directory and Makefile for additional examples.
For playbook examples look into [venafi-playbook-example.yml](tests/venafi-playbook-example.yml) file.
For role examples look into [venafi-role-playbook-example.yml](tests/venafi-role-playbook-example.yml) file

For official documentation about using roles see https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html

Security best practices
----------------

We strongly recommend that you use ansible-vault for the credentials file.
To do so you can use the following steps:

1. Create the `credentials.yml` and populate it with connection parameters:
    ```bash
    cat <<EOF >>credentials.yml
    user: 'admin'
    password: 'secret'
    url: 'https://tpp.venafi.example/vedsdk/'
    zone: "some\\policy"
    EOF
    ```
1. Encrypt it using ansible-vault:
    `ansible-vault encrypt credentials.yml`

1. Add option "--vault-id @prompt" to your ansible-playbook
 command to prompt for vault password:  
    ```bash
    ansible-playbook --vault-id @prompt playbook.yml
    ``` 

For other Vault use cases see https://docs.ansible.com/ansible/latest/user_guide/vault.html


Venafi Platform configuration requirements
----------------
Please refer to this section:  
https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform

License
-------

Apache License Version 2.0

Author Information
------------------

Venafi Inc.
