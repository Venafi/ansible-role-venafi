# Load balancing a set of servers using F5

This example describes the configuration steps required in order to generate a certificate using the venafi ansible role and its installation on a F5 BIG-IP instance in order to load balance a set of http servers and provide [SSL termination](https://www.f5.com/services/resources/glossary/ssl-termination).

## Personas

The steps described in this document are typically performed by a **DevOps Engineer** or a **Systems Administrator**.

## Scenario

A load balancer Application Delivery Controlled (ADC) )is used to increase capacity and reliability of applications, it improves the performance of applications by decreasing the load on the servers associated while managing and maintaining application and network sessions, however its configuration can become a long process, a configuration management tool can be used in order to automate this process.

In this example the load balancer used is a F5 BIG-IP, which once configured should load balance traffic in a cluster of 3 HTTP servers as well as providing SSL termination to it.

## Solution

Use Ansible to automate the process of requesting and retrieving a certificate, installing it and configuring F5 BIG-IP to use it to provide SSL termination and load balancing capabilities to a cluster composed of 3 HTTP servers.

1. Retrieve a certificate using the Venafi ansible role.
2. Copy the certificate files retrieved to the F5 BIG-IP.
3. Create Client SSL Profile on F5 BIG-IP.
4. Create Pool on F5 BIG-IP.
5. Add Pool members on F5 BIG-IP.
6. Create Virtual Server on F5 BIG-IP.

## Prerequisites

> *Note: The sole purpose of the credentials used in this example is illustrative, in a real life scenario they must be considered as weak and insecure.*


To perform the tasks described in this example, you'll need:

- The Venafi ansible role installed on your machine, you can install it using ansible-galaxy [as described here](https://github.com/Venafi/ansible-role-venafi#using-with-ansible-galaxy)
- Access to either **Venafi Trust Protection Platform** or **Venafi Cloud** services (the `credentials.yml` [file](https://github.com/Venafi/ansible-role-venafi#using-with-ansible-galaxy) is used in this example).
- Administration access to the f5 BIG-IP instance. 
- A set of 3 NGINX servers running your application.

## Scenario Introduction

In this example you are going to generate a certificate for the `demo-f5.venafi.example` domain using the Venafi ansible role to request it and retrieve it from either **Venafi Trust Protection Platform** or **Venafi Cloud** services. Then you are going to copy the certificate files (certificate, private key, chain Bundle) to the F5 BIG-IP. Finally you are going to configure F5 BIG-IP to distribute the traffic between 3 NGINX servers using the round-robin load balancing method. Here below you can find a diagram of what we are trying to accomplish.

> *Note: The steps provided in this example suggest the use of the round-robin balancing method, bear in mind there are [other methods](https://www.f5.com/services/resources/glossary/load-balancer) that may be more suitable for your use case scenario.*

![AnsibleVenafi](venafi_ansible_role.png)

## Retrieving certificate using Venafi role

### Creating variables file

The first thing needed is to create the `variables.yml` file, in this file are defined the variables used during the execution of the playbook such as:

- The F5 BIG-IP management IP address.
- The credentials used to manage the F5 BIG-IP.
- The CN needed to generate the certificate.
- The partition in which all the information will be stored.
- The Virtual IP and port on which all the HTTPS traffic will be handled.
- The pool members (the NGINX servers running the application).
- The name for the certificate files which will be copied to the F5 BIG-IP. 
- To facilitate the connection with the device, the connection parameters can be also provided in this file.
  - The pattern used for this is called a **provider**, the provider is a dictionary which includes sub-keys such as *password*, *server*, etc.
  - In the following steps this dictionary will be passed as a parameter to the tasks so they can connect to the BIG-IP.

```yaml
f5_address: "192.168.20.50"
f5_username: "youruser"
f5_password: "yourpassword"

test_site:
  name: "demo-f5"
  domain: "venafi.example"

f5_partition: "Demo" 
f5_virtual_ip: "192.168.7.68"
f5_virtual_port: "443"
f5_pool_members: 
  - host: 192.168.6.201
    port: 8001
  - host: 192.168.6.201
    port: 8002
  - host: 192.168.6.201 
    port: 8003

cert_name: "{{ test_site.name }}.crt"
key_name: "{{ test_site.name }}.key"
chain_name: "{{ test_site.name }}-ca-bundle.crt"

f5_provider:
  server: "{{ f5_address }}"
  server_port: 443
  user: "{{ f5_username }}"
  password: "{{ f5_password }}"
  validate_certs: no
```

### Creating the playbook

Start by creating a YAML file named `f5_create_playbook.yaml`, inside, define a name for the playbook, the hosts in which the tasks will be executed, the type of connection to use and specify the variables file created in the previous step :

```yaml
- name: Create F5 Application
  hosts: localhost
  connection: local

  vars_files:
    - variables.yaml
```


### Requesting an retrieving the certificate using Venafi Role

In the following block of instructions the Venafi Ansible role is being specified along with the variables it needs to request and retrieve the certificate from the Venafi services, by adding these instructions the ansible will:

- Request and retrieve a certificate which common and alternate names are `demo-f5.venafi.example`.
- Create a RSA private key of a size of 2048 bits.
- Generate a chain bundle file where the CA certificate will be place at the end of the file.
- Create a `tmp` directory on the current working directory which will store the retrieved certificate files.
  - 3 files will be retrieved and stored using the names on the variables file (*demonstration.{crt,key,-ca-bundle.crt}*).
- Simulate the copy of the retrieved files to the remote host by generating a duplicate of them adding the `.remote` extension (the certificate files retrieved are going to be copied to F5 BIG-IP using the F5 Ansible modules that's the reason why the options `certificate_copy_private_key_to_remote` and `certificate_remote_execution` are set to `false`).


```yaml
---

  roles:
    - role: venafi.ansible_role_venafi

      certificate_common_name: "{{ test_site.name }}.{{ test_site.domain }}"
      certificate_alt_name: "DNS:{{ test_site.name }}.{{ test_site.domain }}"
      certificate_privatekey_type: "RSA"
      certificate_privatekey_size: "2048"
      certificate_chain_option: "last"

      certificate_cert_dir: "./tmp"
      certificate_cert_path: "./tmp/{{ cert_name }}"
      certificate_chain_path: "./tmp/{{ chain_name }}"
      certificate_privatekey_path: "./tmp/{{ key_name }}"
      certificate_copy_private_key_to_remote: false

      certificate_remote_execution: false
      certificate_remote_privatekey_path: "/tmp/{{ key_name }}.remote"
      certificate_remote_cert_path: "/tmp/{{ cert_name }}.remote"
      certificate_remote_chain_path: "/tmp/{{ chan_name }}.remote"
```

## Copying certificate files to F5 BIG-IP

By adding the instructions below to the playbook, we indicate the actions the  playbook will execute. Ansible will connect to the F5 BIG-IP (using the credentials specified in the provider dictionary) and then it will create the key, CA bundle and certificate using the local files retrieved in the previous step.


```yaml
---

  tasks:
    - name: Create Private Key on F5 BIG-IP {{ f5_address }}
      bigip_ssl_key:
        state: present
        provider: "{{ f5_provider }}"
        name: "{{ key_name }}"
        partition: "{{ f5_partition }}"
        content: "{{ lookup('file', './tmp/' + key_name + '.remote') }}"
      delegate_to: localhost

    - name: Create Certificate on F5 BIG-IP {{ f5_address }}
      bigip_ssl_certificate:
        state: present
        provider: "{{ f5_provider }}"
        name: "{{ cert_name }}"
        partition: "{{ f5_partition }}"
        content: "{{ lookup('file', './tmp/' + cert_name + '.remote') }}"
      delegate_to: localhost

    - name: Create CA Bundle on F5 BIG-IP {{ f5_address }}
      bigip_ssl_certificate:
        state: present
        provider: "{{ f5_provider }}"
        name: "{{ chain_name }}"
        partition: "{{ f5_partition }}"
        content: "{{ lookup('file', './tmp/' + chain_name + '.remote') }}"
      delegate_to: localhost

```

### Creating SSL Client Profile on F5 BIG-IP

After copying the certificate files to the F5 BIG-IP we need to indicate it where those files will be used, this can be don by adding a `Client SSL profile`, which will enable the F5 BIG-IP system to accept and terminate client request that are using SSL, once again we are indicating the credentials used to execute this task on the F5 instance, as well as specifying the certificate files to use.

```yaml
---
    - name: Create Client SSL Profile on F5 BIG-IP {{ f5_address }}
      bigip_profile_client_ssl:
        state: present
        provider: "{{ f5_provider }}"
        name: "clientssl_{{ test_site.name }}"
        partition: "{{ f5_partition }}"
        parent: "clientssl"
        cert_key_chain:
        - cert: "{{ cert_name }}"
          key: "{{ key_name }}"
          chain: "{{ chain_name }}"
      delegate_to: localhost
```

### Creating Pool on F5 BIG-IP

The next step is to add a pool, which is a collection of resources to which F5 will distribute the requests, providing the load balancing [functionality](https://www.f5.com/services/resources/glossary/load-balancer) by using the [round-robin](https://en.wikipedia.org/wiki/Round-robin_scheduling) method, in this case the members of the pool are the NGINX servers defined in the variables file.

```yaml
---

    - name: Create Pool on F5 BIG-IP {{ f5_address }}
      bigip_pool:
        state: present
        provider: "{{ f5_provider }}"
        name: "pool_{{ test_site.name }}"
        partition: "{{ f5_partition }}"
        lb_method: round-robin
      delegate_to: localhost
```

### Adding Pool members on F5 BIG-IP

Once the pool is created, ansible needs to create the pool member in the F5 BIG-IP instance, the members are the ones that will actually serve the requests (NGINX servers hosting the application), ansible will use the host and port variables defined in the variables file for each one of the pool members defined in the `f5_pool_members` dictionary. 

```yaml
---

    - name: Add Pool Members on F5 BIG-IP {{ f5_address }}
      bigip_pool_member:
        state: present
        provider: "{{ f5_provider }}"
        partition: "{{ f5_partition }}"
        host: "{{ item.host }}"
        port: "{{ item.port }}"
        pool: "pool_{{ test_site.name }}"
      with_items: "{{ f5_pool_members }}"
      delegate_to: localhost
```

### Creating Virtual server on F5 BIG-IP

Now that the pool and the nodes are member of the pool, ansible has to create a virtual IP address in order to send the external requests to the pool members. The following task creates the virtual server and assigns it the virtual IP defined in the variables files, as well as the port and Client SSL profile previously created.

```yaml
---

    - name: Create Virtual Server on F5 BIG-IP {{ f5_address }}
      bigip_virtual_server:
        state: present
        provider: "{{ f5_provider }}"
        name: "vs_{{ test_site.name }}"
        partition: "{{ f5_partition }}"
        description: "Provisioned by Ansible"
        destination: "{{ f5_virtual_ip }}"
        port: "{{ f5_virtual_port }}"
        snat: Automap
        pool: "pool_{{ test_site.name }}"
        profiles:
          - "clientssl_{{ test_site.name }}"
      delegate_to: localhost
```

## Executing the playbook

Once the [playbook completed](f5_create_playbook.yaml), it can be executed by running the command below:

```bash
ansible-playbook f5_create_playbook.yaml --ask-vault-pass
```

## Reversing the changes performed

In this example we are including a playbook that allows to revert the changes performed, you can take a look at it [here](f5_delete_playbook.yaml).
