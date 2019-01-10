#!/usr/bin/python
from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
from vcert import CertificateRequest, Connection, CloudConnection, \
    FakeConnection

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: venafi_certificate_module

short_description: This is Venafi certificate module for VCert Python SDK.

version_added: "2.7"

description:
    - "This is Venafi certificate module for VCert Python SDK."

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
# Pass in a message
- name: Test with a message
  my_new_test_module:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_new_test_module:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_new_test_module:
    name: fail me
    
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
      tpp_url: 'https://venafi.example.com/vedsdk'
      tpp_user: 'admin'
      tpp_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
      zone: 'example\\\\policy'
      path: '/tmp'
      tpp_trust_bundle: '/tmp/chain.pem'
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
      api_key: !vault |
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


class VCertificate():

    def __init__(self, module):
        self.test_mode = module.params['test_mode']
        self.tpp_url = module.params['tpp_url']
        self.cloud_url = module.params['cloud_url']
        self.tpp_password = module.params['tpp_password']
        self.tpp_trust_bundle = module.params['tpp_trust_bundle']
        self.api_key = module.params['api_key']
        self.tpp_user = module.params['tpp_user']
        self.zone = module.params['zone']
        self.log_verbose = module.params['log_verbose']
        self.config_file = module.params['config_file']
        self.config_section = module.params['config_section']
        self.args = ""
        self.module = module

        if self.test_mode:
            self.Endpoint = "fake"
            self.EndpointString = "-test-mode"
        elif (self.tpp_url != "" and self.tpp_password != "" and
              self.tpp_user != "" and self.zone):
            self.Endpoint = "tpp"
            if self.tpp_trust_bundle != "":
                self.EndpointString = "-tpp-password " + self.tpp_password + \
                                      " -tpp-url " + self.tpp_url + \
                                      " -tpp-user " + \
                                      self.tpp_user + " -z '" + self.zone \
                                      + "'" + " -trust-bundle " + \
                                      self.tpp_trust_bundle
            else:
                self.EndpointString = "-tpp-password " + self.tpp_password + \
                                      " -tpp-url " + self.tpp_url \
                                      + " -tpp-user " + \
                                      self.tpp_user + " -z '" + self.zone + "'"
        elif self.api_key != "":
            self.Endpoint = "cloud"
            if self.cloud_url != "":
                self.EndpointString = "-k " + self.api_key \
                                      + " -venafi-saas-url " \
                                      + self.cloud_url + " -z '" + \
                                      self.zone + "'"
            else:
                self.EndpointString = "-k " + self.api_key
        else:
            self.Endpoint = "unknown"

    def enroll(self, cn, cert_file="", chain_file="", key_file="", path=""):

        if cert_file == "":
            cert_file = path + "/" + cn + ".pem"
        if chain_file == "":
            chain_file = path + "/" + cn + "_chain.pem"
        if key_file == "":
            key_file = path + "/" + cn + ".key"
        self.args = "vcert enroll -no-prompt " + self.EndpointString\
                    + " -cn " + cn + " -cert-file " + cert_file + " " \
                    "-chain-file " + chain_file + " -key-file " + key_file


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
            provider=dict(type='str', choices=['selfsigned',
                                               'ownca', 'assertonly', 'acme']),
            force=dict(type='bool', default=False, ),
            csr_path=dict(type='path'),

            # Endpoint
            test_mode=dict(type='bool', required=False, default=False),
            tpp_url=dict(type='str', required=False, default=''),
            tpp_trust_bundle=dict(type='str', required=False, default=''),
            cloud_url=dict(type='str', required=False, default=''),
            tpp_password=dict(type='str', required=False, default=''),
            api_key=dict(type='str', required=False, default=''),
            tpp_user=dict(type='str', required=False, default=''),
            zone=dict(type='str', required=False, default=''),
            log_verbose=dict(type='str', required=False, default=''),
            config_file=dict(type='str', required=False, default=''),
            config_section=dict(type='str', required=False, default=''),

            # General properties of a certificate
            path=dict(type='path', required=True),
            common_name=dict(type='str', required=True),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        vcert_args='',
        message='',
        endpoint='',
        error=''
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        return result

    # running vcert command
    vcert = VCertificate(module)
    result['endpoint'] = vcert.Endpoint
    vcert.enroll(cn=module.params['common_name'], path=module.params['path'])
    result['vcert_args'] = vcert.args
    rc, out, err = module.run_command(
        vcert.args, executable="vcert", use_unsafe_shell=False)
    # print(out)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['message'] = out.rstrip(b"\r\n")
    result['error'] = err.rstrip(b"\r\n")

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


if __name__ == '__main__':
    main()
