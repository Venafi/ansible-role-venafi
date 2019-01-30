Role Name
=========

Ansible role Vcert with vcert module in library.  

Requirements
------------

Install vcert using pip:  
`pip install vcert`

Quickstart
------------
1. Install Ansible and vcert via pip  
    `sudo pip install ansible vcert --upgrade` 

1. Prepare demo environment (if you want to use your own environment 
you can skip this step. Change tests/inventory file to use your own inventory.)  

    1. To run test\demo playbook you'll need demo-provision role.
    Download docker-provision role into tests/roles/provision_docker 
    directory  
        ```
        git clone https://github.com/chrismeyersfsu/provision_docker.git \
         tests/roles/provision_docker
        ```
        
    1. Build Docker images needed for the  demo playbook:
    ```bash
    docker build ./tests --tag local-ansible-test
    ```
    
    Demo certificates will be placed on Ansible host into /tmp/ansible/etc/ssl directory,
    from there they will be distributed to the remote hosts into theirs /etc/ssl/ folders.
    
1. Generate credentials file.  
    
    1. For Venafi Platform make following credentials.yml:  
    ```yaml
    user: 'admin'
    password: 'secret'
    url: 'https://venafi.example.com/vedsdk/'
    zone: "example\\\\\\\\policy"
    ```  
    1. For Venafi Cloud set the token in credentials.yml:
    ```yaml
    token: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx"
    zone: "Default"
    ```
    1. Encrypt credentials file using ansible-vault, you will be asked to enter password:
    ```bash
    ansible-vault encrypt credentials.yml
    ```
    
1. Run Ansible playbook (remove docker_demo=true if you want to use your own inventory).
Choice between Cloud and Platform depends on 
credentials provided. If you set a token, the playbook runs on Venafi Cloud.
If you set a password, the playbook runs on Venafi Platform. You will be asked for the vault 
password you entered before.
    ```bash
    ansible-playbook -i tests/inventory \
     tests/venafi-playbook-example.yml \
    --extra-vars "credentials_file=credentials.yml docker_demo=true" \
    --ask-vault-pass
    ```



Role Variables
--------------

```yaml
#Credentials.
venafi:
  # Venafi Platform connection parameters
  user: 'admin'
  password: 'secret'
  url: 'https://venafi.example.com/vedsdk'
  zone: "devops\\\\\\\\vcert",
  # Venafi Cloud connection parameters
  #token: 'enter-cloud-api-token-here'
  #zone: 'Default'
  #Test mode parameter
  #test_mode: true

credentials_file: credentials.yml

#Certificate parameters. This is are examples.
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

#Where to execute venafi_certificate module. If set to false, certificate will be
#created on ansible master host and then copied to the remote server
certificate_remote_execution: false
#  remote location where to place the certificate_
certificate_remote_cert_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.pem"
certificate_remote_chain_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.chain.pem"
certificate_remote_privatekey_path: "{{ certificate_cert_dir }}/{{ certificate_common_name }}.key"
# Set to false if you don't want to copy private key to remote location
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

playbook file example:  

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

      #Where to execute venafi_certificate module. If set to false certificate will be
      #created on ansible master host and then copied to the remote server
      certificate_remote_execution: false
      #  remote location where to place the certificate.
      certificate_remote_cert_dir: "/etc/ssl"
      certificate_remote_cert_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.pem"
      certificate_remote_chain_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.chain.pem"
      certificate_remote_privatekey_path: "{{ certificate_remote_cert_dir }}/{{ certificate_common_name }}.key"
      # Set to false if you don't want to copy private key to remote location
      certificate_copy_private_key_to_remote: true

```

credentials files examples:  

for Venafi Platform:

```yaml
user: 'admin'
password: 'secret'
url: 'https://venafi.example.com/vedsdk/'
zone: "some\\\\\\\\policy"

```

for Venafi Cloud:  

```yaml
token: "xxxxx-xxxxx-xxxxx-xxxx-xxxxx"
zone: "Default"
```

By default credentials are read from file credentials.yml you can rewrite it 
with variable credentials_file  
For example:  

    ansible-playbook playbook.yml --extra-vars "credentials_file=other_credentials.yml"

Look into tests directory and Makefile for more examples.

Look into official documentation about using roles: https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html

Security best practices
----------------

We are strongly recommend that you use ansible-vault for the credentials file
to do so you can do the following steps:

1. Create the credentials.yml and fill it with connection parameters:
    ```bash
    cat <<EOF >>credentials.yml
    user: 'admin'
    password: 'secret'
    url: 'https://venafi.example.com/vedsdk/'
    zone: "some\\\\\\\\policy"
    EOF
    ```
1. Encrypt it with ansible-vault:
    `ansible-vault encrypt credentials.yml`

1. Add option "--vault-id @prompt" to your ansible-playbook
 command to prompt for vault password:  
    ```bash
    ansible-playbook --vault-id @prompt playbook.yml
    ``` 

For other Vault use cases see official documentation:
https://docs.ansible.com/ansible/latest/user_guide/vault.html


Venafi Platform configuration notice
----------------
Please refer to this section:  
https://github.com/Venafi/vcert-python#prerequisites-for-using-with-trust-protection-platform

License
-------

Apache License Version 2.0

Author Information
------------------

Venafi Inc.
