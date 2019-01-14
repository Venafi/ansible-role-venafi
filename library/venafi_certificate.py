#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
import time
from vcert import CertificateRequest, Connection

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
            state=dict(type='str', choices=['present', 'absent'],
                       default='present'),
            force=dict(type='bool', default=False, ),

            # Endpoint
            test_mode=dict(type='bool', required=False, default=False),
            url=dict(type='str', required=False, default=''),
            password=dict(type='str', required=False, default=''),
            token=dict(type='str', required=False, default=''),
            user=dict(type='str', required=False, default=''),
            zone=dict(type='str', required=False, default=''),
            log_verbose=dict(type='str', required=False, default=''),
            config_file=dict(type='str', required=False, default=''),
            config_section=dict(type='str', required=False, default=''),

            # General properties of a certificate
            path=dict(type='path', require=False),
            chain_path=dict(type='path', require=False),
            privatekey_path=dict(type='path', required=False),
            privatekey_passphrase=dict(type='str', no_log=True),
            signature_algorithms=dict(type='list', elements='str'),
            subjectAltName=dict(type='list', aliases=['subject_alt_name'], elements='str'),
            commonName=dict(aliases=['CN', 'common_name'], type='str'),
---
module: venafi_certificate_module

short_description: This is Venafi certificate module for working with
Venafi Cloud or Venafi Trusted Platform

version_added: "2.7"

description:
    - This is Venafi certificate module for working with Venafi Cloud or
     Venafi Trusted Platform "

options:
    path:
        required: true
        description:
            - Remote absolute path where the generated certificate file should
            be created or is already located.

    chain_path:
        required: false
        description:
            - Remote absolute path where the generated certificate chain file should
            be created or is already located.
                
    common_name:
        required: false
        aliases: [ 'CN', 'commonName' ]
        description:
            - commonName field of the certificate signing request subject
    email_address:
        required: false
        aliases: [ 'E', 'emailAddress' ]
        description:
            - emailAddress field of the certificate signing request subject
    subject_alt_name:
        required: false
        aliases: [ 'subjectAltName' ]
        description:
            - SAN extension to attach to the certificate signing request
            - This can either be a 'comma separated string' or a YAML list.
            - Values should be prefixed by their options. (i.e., C(email), C(URI), C(DNS), C(RID), C(IP), C(dirName),
              C(otherName) and the ones specific to your CA)
            - More at U(https://tools.ietf.org/html/rfc5280#section-4.2.1.6)
            
    privatekey_path:
        required: true
        description:
            - Path to the privatekey to use when signing the certificate signing request
            
    privatekey_passphrase:
        required: false
        description:
            - The passphrase for the privatekey.
                        
extends_documentation_fragment:
    - files

author:
    - Alexander Rykalin (@arykalin)
'''

EXAMPLES = '''
# Enroll fake certificate for testing purposes
- name: venafi_certificate_fake
  connection: local
  hosts: localhost
  tags:
    - fake
  tasks:
  - name: venafi_certificate
    venafi_certificate:
      test_mode: true
      common_name: 'testcert-fake-{{ 99999999 | random }}.example.com'
      path: '/tmp'
    register: testout
  - name: dump test output
    debug:
      msg: '{{ testout }}'

# Enroll Platform certificate
- name: venafi_certificate_tpp
  connection: local
  hosts: localhost
  tags:
    - tpp
  tasks:
  - name: venafi_certificate
    venafi_certificate:
      url: 'https://venafi.example.com/vedsdk'
      user: 'admin'
      password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
      zone: 'example\\\\policy'
      path: '/tmp'
      common_name: 'testcert-tpp-{{ 99999999 | random }}.example.com'
      subject_alt_name: 'DNS:www.ansible.com,DNS:m.ansible.com'
    register: testout
  - name: dump test output
    debug:
      msg: '{{ testout }}'

# Enroll Cloud certificate
- name: venafi_certificate_cloud
  connection: local
  hosts: localhost
  tags:
    - cloud
  tasks:
  - name: venafi_certificate
    venafi_certificate:
      token: !vault |
          $ANSIBLE_VAULT;1.1;AES256
      zone: 'Default'
      path: '/tmp'
      common_name: 'testcert-cloud.example.com'
    register: testout
  - name: dump test output
    debug:
      msg: '{{ testout }}'
'''

RETURN = '''
privatekey:
    description: Path to the TLS/SSL private key the CSR was generated for
    returned: changed or success
    type: string
    sample: /etc/ssl/private/ansible.com.pem
    
privatekey_size:
    description: Size (in bits) of the TLS/SSL private key
    returned: changed or success
    type: int
    sample: 4096
privatekey_type:
    description: Algorithm used to generate the TLS/SSL private key
    returned: changed or success
    type: string
    sample: RSA
        
certificate_filename:
    description: Path to the signed Certificate Signing Request
    returned: changed or success
    type: string
    sample: /etc/ssl/csr/www.ansible.com.csr

chain_filename:
'''



class VCertificate:

    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.test_mode = module.params['test_mode']
        self.url = module.params['url']
        self.password = module.params['password']
        self.token = module.params['token']
        self.user = module.params['user']
        self.zone = module.params['zone']
        self.args = ""
        self.module = module
        self.conn = Connection(url=self.url, token=self.token,
                               user=self.user, password=self.password,
                               ignore_ssl_errors=True)

    def ping(self):
        print("Trying to ping url %s" % self.conn)
        status = self.conn.ping()
        print("Server online:", status)
        if not status:
            print('Server offline - exit')
            exit(1)

    def enroll(self):

        request = CertificateRequest(common_name=self.module['commonName'])
        #TODO: make a function to recognise extension type
        request.san_dns = ["www.client.venafi.example.com", "ww1.client.venafi.example.com"]
        request.email_addresses = ["e1@venafi.example.com", "e2@venafi.example.com"]
        request.ip_addresses = ["127.0.0.1", "192.168.1.1"]
        request.chain_option = "last"

        self.conn.request_cert(request, self.zone)
        while True:
            cert = self.conn.retrieve_cert(request)
            if cert:
                break
            else:
                time.sleep(5)

    def dump(self):

        result = {
            'changed': self.changed,
            'filename': self.path,
            'privatekey': self.privatekey_path,
            'csr': self.csr_path,
            'ca_cert': self.ca_cert_path,
            'ca_privatekey': self.ca_privatekey_path
        }

        return result


def main():
    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        # define the available arguments/parameters that a user can pass to
        # the module
        argument_spec=dict(
            state=dict(type='str', choices=['present', 'absent'],
                       default='present'),
            force=dict(type='bool', default=False, ),

            # Endpoint
            test_mode=dict(type='bool', required=False, default=False),
            url=dict(type='str', required=False, default=''),
            password=dict(type='str', required=False, default=''),
            token=dict(type='str', required=False, default=''),
            user=dict(type='str', required=False, default=''),
            zone=dict(type='str', required=False, default=''),
            log_verbose=dict(type='str', required=False, default=''),
            config_file=dict(type='str', required=False, default=''),
            config_section=dict(type='str', required=False, default=''),

            # General properties of a certificate
            path=dict(type='path', require=False),
            chain_path=dict(type='path', require=False),
            privatekey_path=dict(type='path', required=False),
            privatekey_passphrase=dict(type='str', no_log=True),
            signature_algorithms=dict(type='list', elements='str'),
            subjectAltName=dict(type='list', aliases=['subject_alt_name'], elements='str'),
            commonName=dict(aliases=['CN', 'common_name'], type='str'),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )

    vcert = VCertificate(module)
    vcert.ping()
    vcert.enroll()

    result = vcert.dump()
    result['changed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
