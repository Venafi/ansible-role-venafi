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
---
module: venafi_certificate_module

short_description: This is Venafi certificate module for working with Venafi Cloud or Venafi Trusted Platform 

version_added: "2.7"

description:
    - This is Venafi certificate module for working with Venafi Cloud or Venafi Trusted Platform "

options:
    path:
        required: true
        description:
            - Remote absolute path where the generated certificate file should
            be created or is already located.

extends_documentation_fragment:
    - azure

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
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
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
        self.conn = Connection(url=self.url, token=self.token, user=self.user, password=self.password, ignore_ssl_errors=True)


    def ping(self):
        print("Trying to ping url %s" % self.conn)
        status = self.conn.ping()
        print("Server online:", status)
        if not status:
            print('Server offline - exit')
            exit(1)

    def enroll(self):


        request = CertificateRequest(common_name=self.module['subject'])
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
            subject=dict(type='str'),
            subjectAltName=dict(type='list', aliases=['subject_alt_name'], elements='str'),
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
