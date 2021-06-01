#!/usr/bin/env python3
#
# Copyright 2021 Venafi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import random

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.venafi.machine_identity.plugins.module_utils.venafi_connection import Venafi

HAS_VCERT = True
try:
    from vcert.parser import json_parser, yaml_parser
    from vcert.policy import PolicySpecification, Policy
except ImportError:
    HAS_VCERT = False

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: venafi_policy_management_module

short_description: This is Venafi policy management module for working with
Venafi as a Service (VaaS) or Venafi Trusted Protection Platform (TPP)

version_added: "2.7"

description:
    - This is Venafi policy management module for working with Venafi as a Service (VaaS) 
    or Venafi Trusted Protection Platform (TPP)

options:
    force:
        default: False
        type: bool
        description:
            - Generate the certificate, even if it already exists.

    state:
        default: "present"
        choices: [ present, absent ]
        description:
            - > Whether the certificate should exist or not,
            taking action if the state is different from what is stated.

    renew:
        default: True
        type: bool
        description:
            - Try to renew certificate if is existing but not valid.

    cert_path:
        required: true
        description:
            - Remote absolute path where the generated certificate file should
            be created or is already located.

   
extends_documentation_fragment:
    - files

author:
    - Russel Vela (@rvelamia)
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
      alt_name: 'DNS:www.venafi.example,DNS:m.venafi.example'
      cert_path: '/tmp'
    register: certout
  - name: dump test output
    debug:
      msg: '{{ certout }}'

# Enroll Platform certificate with a lot of alt names
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
      cert_path: '/tmp'
      common_name: 'testcert-tpp-{{ 99999999 | random }}.example.com'
      alt_name: |
        IP:192.168.1.1,DNS:www.venafi.example.com,
        DNS:m.venafi.example.com,email:test@venafi.com,IP Address:192.168.2.2
    register: certout
  - name: dump test output
    debug:
      msg: '{{ certout }}'

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
      cert_path: '/tmp'
      common_name: 'testcert-cloud.example.com'
    register: certout
  - name: dump test output
    debug:
      msg: '{{ certout }}'
'''

RETURN = '''
privatekey_filename:
    description: Path to the TLS/SSL private key the CSR was generated for
    returned: changed or success
    type: string
    sample: /etc/ssl/private/venafi.example.pem

privatekey_size:
    description: Size (in bits) of the TLS/SSL private key
    returned: changed or success
    type: int
    sample: 4096

privatekey_curve:
    description: > ECDSA curve of generated private key. Variants are "P521",
     "P384", "P256", "P224".

    returned: changed or success
    type: string
    sample: "P521"

privatekey_type:
    description: > Algorithm used to generate the TLS/SSL private key.
    Variants are RSA or ECDSA

    returned: changed or success
    type: string
    sample: RSA

certificate_filename:
    description: Path to the signed certificate
    returned: changed or success
    type: string
    sample: /etc/ssl/www.venafi.example.pem

chain_filename:
    description: > Path to the chain of CA certificates that link
    the certificate to a trust anchor

    returned: changed or success
    type: string
    sample: /etc/ssl/www.venafi.example_chain.pem
'''

F_CHANGED = 'changed'
F_CHANGED_MSG = 'changed_msg'
F_OUTPUT_FILE_EXISTS = 'policy_spec_output_file_exists'
F_OPERATION = 'operation'
V_OPERATION_CREATE = 'create'
V_OPERATION_READ = 'read'


class VPolicyManagement:

    def __init__(self, module):
        """
        :param AnsibleModule module: The module containing the necessary parameters to perform the operations
        """
        self.module = module
        self.changed = False
        self.venafi = Venafi(module)
        self.zone = module.params['zone']
        self.ps_source = module.params['policy_spec_src_path']
        self.ps_output = module.params['policy_spec_output_path']

    def validate(self):
        """
        Ensures the policy specification resource is in its desired state.
        Otherwise raises an error

        :return: None
        """
        result = self.check()
        if result[F_CHANGED]:
            self.module.fail_json(
                msg=result[F_CHANGED_MSG]
            )

    def check(self):
        """
        Validates if the resources have changed since the last execution

        :return: a dictionary with the results of the validation
        :rtype: dict[str, Any]
        """
        result = {
            F_CHANGED: False,
            F_OUTPUT_FILE_EXISTS: True,
            F_OPERATION: V_OPERATION_CREATE
        }
        msgs = []
        src_exists = False
        if os.path.exists(self.ps_source):
            src_exists = True

        if not os.path.exists(self.ps_output):
            result = {
                F_CHANGED: True,
                F_OUTPUT_FILE_EXISTS: False,
                F_OPERATION: (V_OPERATION_CREATE if src_exists else V_OPERATION_READ)
            }
            msgs.append('Policy Specification output file does not exist'),
        else:
            if src_exists:
                # Source PS exists, output PS is the result of a create operation.
                # Validate all fields in the source PS are the same in the output PS
                is_changed, changed_msgs = self._check_policy_specification()
                result[F_CHANGED] = is_changed
                msgs.append(changed_msgs)
            else:
                # Source PS does not exist. output PS is the result of a read operation.
                result[F_OPERATION] = V_OPERATION_READ

        result[F_CHANGED_MSG] = ' | '.join(msgs)
        return result

    def _check_policy_specification(self):
        """
        Validates that all values present in the source PolicySpecification match with
        the current output PolicySpecification

        :rtype: tuple[bool, list[str]]
        """
        out_ps = self._read_policy_spec_file(self.ps_output)
        src_ps = self._read_policy_spec_file(self.ps_source)
        is_changed = False
        msgs = []
        if not self._check_list(out_ps.owners, src_ps.owners):
            is_changed = True
            msgs.append('')
        if not self._check_list(out_ps.users, src_ps.users):
            is_changed = True
            msgs.append('')
        if not self._check_list(out_ps.approvers, src_ps.approvers):
            is_changed = True
            msgs.append('')
        if not self._check_value(out_ps.user_access, src_ps.user_access):
            is_changed = True
            msgs.append('')

        # Validate all Policy values match
        if (src_ps.policy is None and out_ps.policy is not None) \
                or (src_ps.policy is not None and out_ps.policy is None):
            is_changed = True
            msgs.append('')
        else:
            src_p = src_ps.policy
            out_p = out_ps.policy
            if not self._check_list(out_p.domains, src_p.domains):
                is_changed = True
                msgs.append('')
            for src, out in {(src_p.wildcard_allowed, out_p.wildcard_allowed),
                             (src_p.max_valid_days, out_p.max_valid_days),
                             (src_p.certificate_authority, out_p.certificate_authority),
                             (src_p.auto_installed, out_p.auto_installed)}:
                if not self._check_value(out, src):
                    is_changed = True
                    msgs.append('')

            if (src_p.subject is None and out_p.subject is not None) \
                    or (src_p.subject is not None and out_p.subject is None):
                is_changed = True
                msgs.append('')
            else:
                src_subject = src_p.subject
                out_subject = out_p.subject
                for src, out in {(src_subject.orgs, out_subject.orgs),
                                 (src_subject.org_units, out_subject.org_units),
                                 (src_subject.localities, out_subject.localities),
                                 (src_subject.states, out_subject.states),
                                 (src_subject.countries, out_subject.countries)}:
                    if not self._check_list(out, src):
                        is_changed = True
                        msgs.append('')

            if (src_p.key_pair is None and out_p.key_pair is not None) \
                    or (src_p.key_pair is not None and out_p.key_pair is None):
                is_changed = True
                msgs.append('')
            else:
                src_kp = src_p.key_pair
                out_kp = out_p.key_pair
                for src, out in {(src_kp.service_generated, out_kp.service_generated),
                                 (src_kp.reuse_allowed, out_kp.reuse_allowed)}:
                    if not self._check_value(out, src):
                        is_changed = True
                        msgs.append('')
                for src, out in {(src_kp.key_types, out_kp.key_types),
                                 (src_kp.rsa_key_sizes, out_kp.rsa_key_sizes),
                                 (src_kp.elliptic_curves, out_kp.elliptic_curves)}:
                    if not self._check_list(out, src):
                        is_changed = True
                        msgs.append('')

            if (src_p.subject_alt_names is None and out_p.subject_alt_names is not None) \
                    or (src_p.subject_alt_names is not None and out_p.subject_alt_names is None):
                is_changed = True
                msgs.append('')
            else:
                src_sans = src_p.subject_alt_names
                out_sans = out_p.subject_alt_names
                for src, out in {(src_sans.dns_allowed, out_sans.dns_allowed),
                                 (src_sans.email_allowed, out_sans.email_allowed),
                                 (src_sans.ip_allowed, out_sans.ip_allowed),
                                 (src_sans.upn_allowed, out_sans.upn_allowed),
                                 (src_sans.uri_allowed, out_sans.uri_allowed)}:
                    if not self._check_value(out, src):
                        is_changed = True
                        msgs.append('')

        # Validate all Default values match
        if (src_ps.defaults is None and out_ps.defaults is not None)\
                or (src_ps.defaults is not None and out_ps.defaults is None):
            is_changed = True
            msgs.append('')
        else:
            src_d = src_ps.defaults
            out_d = out_ps.defaults
            for src, out in {(src_d.domain, out_d.domain),
                             (src_d.auto_installed, out_d.auto_installed)}:
                if not self._check_value(out, src):
                    is_changed = True
                    msgs.append('')

            # Validate all default subject values match
            if (src_d.subject is None and out_d.subject is not None) \
                    or (out_d.subject is not None and out_d.subject is None):
                is_changed = True
                msgs.append('')
            else:
                src_ds = src_d.subject
                out_ds = out_d.subject
                if not self._check_list(out_ds.org_units, src_ds.org_units):
                    is_changed = True
                    msgs.append('')
                for src, out in {(src_ds.org, out_ds.org),
                                 (src_ds.locality, out_ds.locality),
                                 (src_ds.state, out_ds.state),
                                 (src_ds.country, out_ds.country)}:
                    if not self._check_value(out, src):
                        is_changed = True
                        msgs.append('')

            # Validate all default Key Pair values match
            if (src_d.key_pair is None and out_d.key_pair is not None) \
                    or (src_d.key_pair is not None and out_d.key_pair is None):
                is_changed = True
                msgs.append('')
            else:
                src_dkp = src_d.key_pair
                out_dkp = out_d.key_pair
                for src, out in {(src_dkp.elliptic_curve, out_dkp.elliptic_curve),
                                 (src_dkp.key_type, out_dkp.key_type),
                                 (src_dkp.rsa_key_size, out_dkp.rsa_key_size),
                                 (src_dkp.service_generated, out_dkp.service_generated)}:
                    if not self._check_value(out, src):
                        is_changed = True
                        msgs.append('')

        return is_changed, msgs

    @staticmethod
    def _check_list(output_values, src_values):
        """
        Tests that all the elements of the sublist are present in the collection

        :param list output_values: The tested values
        :param list src_values: The member values
        :rtype: bool
        """
        if len(output_values) == len(src_values):
            return all(x in src_values for x in output_values)
        else:
            return False

    @staticmethod
    def _check_value(output_value, src_value):
        """
        Validates if both parameters are equal.

        :param output_value:
        :param src_value:
        :return: True if both parameters hold the same value, False otherwise
        :rtype: bool
        """
        if output_value is not None and src_value is not None:
            return True if output_value == src_value else False
        elif output_value is None and src_value is None:
            return True
        else:
            return False

    def _read_policy_spec_file(self, ps_filename):
        """
        Reads the content of the given file and parses it to a PolicySpecification object
        that Venafi can use to create policies

        :param str ps_filename: The path of the PolicySpecification file to read
        :rtype: PolicySpecification
        """
        parser = self._get_policy_spec_parser(ps_filename)
        ps = parser.parse(ps_filename) if parser else None
        if not ps:
            self.module.fail_json(msg='Unknown file. Could not read data from %s' % ps_filename)

        return ps

    @staticmethod
    def _get_policy_spec_parser(ps_filename):
        """
        Returns the specific parser for a given file based on the file extension.
        Only supports json and yaml/yml files

        :param ps_filename: the path of the file to be read by the parser
        :return: a parser implementation
        :rtype: json_parser or yaml_parser
        """
        path_tuple = os.path.splitext(ps_filename)
        if path_tuple[1] == 'json':
            return json_parser
        elif path_tuple[1] in ['yaml', 'yml']:
            return yaml_parser

        return None

    def check_dirs_exist(self):
        """
        Validates that the parent directories for the source and ouput PolicySpecification files
        do exist.

        :return: True if parent directories exist, False otherwise
        :rtype: bool
        """
        src_dir = os.path.dirname(self.ps_source or "/a")
        output_dir = os.path.dirname(self.ps_output or "/a")
        ok = True
        for p in {src_dir, output_dir}:
            if os.path.isdir(p):
                continue
            elif os.path.exists(p):
                self.module.fail_json(
                    msg="Path %s already exists but this is not directory" % p)
            elif not os.path.exists(p):
                self.module.fail_json(msg="Directory %s does not exists" % p)
            ok = False
        return ok

    def set_policy(self):
        """
        Reads the content of the source PolicySpecification and creates a policy in Venafi
        with the zone as name

        :return: Nothing
        """
        parser = self._get_policy_spec_parser(self.ps_source)
        source_ps = parser.load_file(self.ps_source) if parser else None
        if source_ps:
            try:
                self.venafi.connection.set_policy(self.zone, source_ps)
                self.get_policy()
            except Exception as e:
                self.module.fail_json('Failed to create/update policy %s: %s' % (self.zone, e))
        else:
            self.module.fail_json(msg='Could not get a parser for the file %s. Unknown extension.' % self.ps_source)

    def get_policy(self):
        """
        Retrieves an existing policy (specified by the zone) from Venafi and writes it to a file

        :return: Nothing
        """
        ps = self.venafi.connection.get_policy(self.zone)
        self._atomic_write(self.ps_output, ps)

    def _atomic_write(self, path, content):
        """
        Writes the given content to a file specified by the path.

        :param path: the path of the file to be written
        :param content: the content to write in the file
        :return: Nothing
        """
        suffix = ".atomic_%s" % random.randint(100, 100000)
        try:
            parser = self._get_policy_spec_parser(path)
            if parser:
                parser.serialize(content, path + suffix)
            else:
                raise Exception('Could not get a parser for the file %s. Unknown extension.' % path)
        except Exception as e:
            self.module.fail_json(msg="Failed to write file %s: %s" % (
                path + suffix, e))

        self.module.atomic_move(path + suffix, path)
        self.changed = True
        self._check_and_update_permissions(path)

    def _check_and_update_permissions(self, path):
        """

        :param path:
        :return: Nothing
        """
        file_args = self.module.load_file_common_arguments(self.module.params)
        file_args['path'] = path
        if self.module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    def dump(self):
        """
        Returns the resources used by this module and its state
        :return: a dictionary with the values of the resources used by this module
        :rtype: dict[str, Any]
        """
        result = {
            'changed': self.changed,
            'policy_spec_src_filename': self.ps_source,
            'policy_spec_output_filename': self.ps_output,
            'zone': self.zone
        }
        return result


def main():
    module = AnsibleModule(
        # define the available arguments/parameters that a user can pass to
        # the module
        argument_spec=dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            force=dict(type='bool', default=False),
            # Endpoint
            test_mode=dict(type='bool', required=False, default=False),
            url=dict(type='str', required=False, default=''),
            user=dict(type='str', required=False, default='', no_log=True),
            password=dict(type='str', required=False, default='', no_log=True),
            token=dict(type='str', required=False, default='', no_log=True),
            access_token=dict(type='str', required=False, default='', no_log=True),
            trust_bundle=dict(type='str', required=False),
            zone=dict(type='str', required=True),
            # Policy Management
            policy_spec_src_path=dict(type='path', required=False),
            policy_spec_output_path=dict(type='path', required=True),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )
    if not HAS_VCERT:
        module.fail_json(msg='"vcert" python library is required')

    vcert = VPolicyManagement(module)
    change_dump = vcert.check()
    if module.check_mode:
        module.exit_json(**change_dump)

    if not vcert.check_dirs_exist():
        module.fail_json(msg="Dirs do not exist")

    if change_dump[F_CHANGED]:
        # Create/Update a Policy Specification
        if change_dump[F_OPERATION] == V_OPERATION_CREATE:
            vcert.set_policy()
        # Read a Policy Specification from Venafi
        elif change_dump[F_OPERATION] == V_OPERATION_READ:
            vcert.get_policy()

    vcert.validate()
    result = vcert.dump()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
