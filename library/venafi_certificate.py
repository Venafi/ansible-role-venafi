#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: venafi_certificate_module

short_description: This is Venafi certificate module for working with
Venafi Cloud or Venafi Trusted Platform

version_added: "2.7"

description:
    - This is Venafi certificate module for working with Venafi Cloud or
     Venafi Trusted Platform "

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
            - Whether the certificate should exist or not, taking action if the state is different from what is stated.

    renew:
        default: False
        type: bool
        description:
            - Try to renew certificate if is existing but no valid.

    path:
        required: true
        description:
            - Remote absolute path where the generated certificate file should
            be created or is already located.

    chain_path:
        required: false
        description:
            - Remote absolute path where the generated certificate chain file should
            be created or is already located. If set certificate and chain will be in separated files.

    chain_option:
        required: false
        default: "last"
        description:
            - Specify ordering certificates in chain. Root can be "first" or "last"
                
    common_name:
        required: false
        aliases: [ 'CN', 'commonName' ]
        description:
            - commonName field of the certificate signing request subject

    alt_name:
        required: false
        aliases: [ 'alt_name' ]
        description:
            - SAN extension to attach to the certificate signing request
            - This can either be a 'comma separated string' or a YAML list.
            - Values should be prefixed by their options. (IP:,email:,DNS:)
            
    privatekey_path:
        required: false
        description:
            - Path to the privatekey to use when signing the certificate signing request. If not set will be placed 
            near certificate with key suffix.

    privatekey_type:
        default: "RSA"
        required: false
        description:
            - Type of private key. RSA or ECDSA

    privatekey_size:
        required: false
        default: 2048
        description:
            - Size (in bits) of the TLS/SSL key to generate. Used only for RSA. 

    privatekey_curve:
        required: false
        default: "P521"
        description:
            - Curves name for ecdsa algorithm. Choices are "P521", "P384", "P256", "P224".

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
      alt_name: 'DNS:www.venafi.example,DNS:m.venafi.example'
      path: '/tmp'
    register: testout
  - name: dump test output
    debug:
      msg: '{{ testout }}'

# Enroll Platform certificate with a lof of alt names
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
      "alt_name": "IP:192.168.1.1,DNS:www.venafi.example.com,DNS:m.venafi.example.com,email:test@venafi.com,IP Address:192.168.2.2"
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
    description: ECDSA curve of generated private key. Variants are "P521", "P384", "P256", "P224".
    returned: changed or success
    type: string
    sample: "P521"
    
privatekey_type:
    description: Algorithm used to generate the TLS/SSL private key. Variants are RSA or ECDSA
    returned: changed or success
    type: string
    sample: RSA
        
certificate_filename:
    description: Path to the signed Certificate Signing Request
    returned: changed or success
    type: string
    sample: /etc/ssl/www.venafi.example.pem

chain_filename:
    description: Path to the signed Certificate Signing Request
    returned: changed or success
    type: string
    sample: /etc/ssl/www.venafi.example_chain.pem
'''

# TODO:  raise JSON error messages when dependency import fails.
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_text
import time
import datetime
import os.path
import random
from vcert import CertificateRequest, Connection
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes

class VCertificate:

    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.common_name = module.params['commonName']
        self.alt_name = module.params['alt_name']
        self.test_mode = module.params['test_mode']
        self.url = module.params['url']
        self.password = module.params['password']
        self.token = module.params['token']
        self.user = module.params['user']
        self.zone = module.params['zone']
        self.privatekey_filename = module.params['privatekey_path']
        self.certificate_filename = module.params['path']
        self.privatekey_type = module.params['privatekey_type']
        self.privatekey_curve = module.params['privatekey_curve']
        self.privatekey_size = module.params['privatekey_size']
        self.privatekey_passphrase = module.params['privatekey_passphrase']
        self.chain_filename = module.params['chain_path']
        self.args = ""
        self.changed = False
        self.module = module
        self.conn = Connection(url=self.url, token=self.token,
                               user=self.user, password=self.password,
                               ignore_ssl_errors=True)

    def ping(self):
        print("Trying to ping url %s" % self.conn._base_url)
        status = self.conn.ping()
        print("Server online:", status)
        if not status:
            print('Server offline - exit')
            exit(1)

    def check_paths_existed(self):
        cert_dir = os.path.dirname(self.certificate_filename or "/a")
        key_dir = os.path.dirname(self.privatekey_filename or "/a")
        chain_dir = os.path.dirname(self.chain_filename or "/a")
        for p in (cert_dir, key_dir, chain_dir):
            if os.path.isdir(p):
                continue
            elif os.path.exists(p):
                self.module.fail_json(msg="Path %s already exists but this is not directory." % p)
            os.makedirs(p)

    def check_private_key_correct(self):
        if not self.privatekey_filename:
            return None
        private_key = to_text(open(self.privatekey_filename, "rb").read())

        r = CertificateRequest(private_key=private_key, key_password=self.privatekey_passphrase)
        key_type = {"RSA": "rsa", "ECDSA": "ec", "EC": "ec"}.get(self.privatekey_type)
        if key_type and key_type != r.key_type:
            return False
        if key_type == "rsa" and self.privatekey_size:
            if self.privatekey_size != r.key_length:
                return False
        if key_type == "ec" and self.privatekey_curve:
            if self.privatekey_curve != r.key_curve:
                return False
        return True


    def enroll(self):
        # TODO: Check if certificate in path parameter already exists.

        # TODO: add possibility to provide own CSR
        request = CertificateRequest(
            common_name=self.common_name,
            key_password=self.privatekey_passphrase,

        )

        if self.privatekey_filename:
            private_key = to_text(open(self.privatekey_filename, "rb").read())
            request.private_key = private_key
        elif self.privatekey_type:
            key_type = {"RSA": "rsa", "ECDSA": "ec", "EC": "ec"}.get(self.privatekey_type)
            if not key_type:
                self.module.fail_json(msg="Failed to determine key type: {0}. Must be RSA or ECDSA".format(
                    self.privatekey_type))
            request.key_type = key_type
            request.key_curve = self.privatekey_curve
            request.key_length = self.privatekey_size

        request.ip_addresses = []
        request.san_dns = []
        request.email_addresses = []
        if self.alt_name:
            for n in self.alt_name:
                if n.startswith(("IP:", "IP Address:")):
                    ip = n.split(":", 1)[1]
                    request.ip_addresses.append(ip)
                elif n.startswith("DNS:"):
                    ns = n.split(":", 1)[1]
                    request.san_dns.append(ns)
                elif n.startswith("email:"):
                    mail = n.split(":", 1)[1]
                    request.email_addresses.append(mail)
                else:
                    self.module.fail_json(msg="Failed to determine extension type: {0}".format(n))


        request.chain_option = self.module.params['chain_option']

        self.conn.request_cert(request, self.zone)
        while True:
            cert = self.conn.retrieve_cert(request)
            if cert:
                break
            else:
                time.sleep(5)
        # TODO: Optionaly separate certificate and it's chain (if chain exists) into different files.
        # TODO: Don’t write to files directly; use a temporary file and then use the atomic_move function from ansible.module_utils.basic
        #  to move the updated temporary file into place.
        #  This prevents data corruption and ensures that the correct context for the file is kept.
        try:
            with open(self.certificate_filename, 'wb') as certfile:
                certfile.write(to_bytes(cert))
            self.changed = True
        except OSError as exc:
            self.module.fail_json(msg="Failed to write certificate file: {0}".format(exc))

        try:
            with open(self.privatekey_filename, 'wb') as keyfile:
                keyfile.write(to_bytes(request.private_key_pem))
            self.changed = True
        except OSError as exc:
            self.module.fail_json(msg="Failed to write private key file: {0}".format(exc))

    def _atomic_write(self, path, content):
        suffix = ".atomic_%s" % random.randint(100, 100000)
        try:
            with open(path+suffix, "wb") as f:
                f.write(to_bytes(content))
        except OSError as e:
            self.module.fail_json(msg="Failed to write file %s: %s" % (path+suffix, e))
        try:
            os.rename(path+suffix, path)
        except OSError as e:
            self.module.fail_json(msg="Failed to atomic replace file %s by %s: %s" % (path, path+suffix, e))

    def check_certificate_validity(self):
        try:
            with open(self.certificate_filename, 'rb') as cert_data:
                cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())  # type: x509.Certificate
        except OSError as exc:
            self.module.fail_json(msg="Failed to read certificate file: {0}".format(exc))
            return
        if cert.subject != self.common_name:
            return False
        if cert.not_valid_after < datetime.datetime.now() - datetime.timedelta(days=2):  # todo: move day to parameter
            return False
        if cert.not_valid_before > datetime.datetime.now():  # todo: think add gap for time desyncronyzation
            return False
        # TODO: Test what extensions are the same as required

    def check(self):
        """Ensure the resource is in its desired state."""
        try:
            with open(self.certificate_filename, 'rb') as cert_data:
                cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())
        except OSError as exc:
            self.module.fail_json(msg="Failed to read certificate file: {0}".format(exc))
        if self.privatekey_filename:
            try:
                with open(self.privatekey_filename, 'rb') as key_data:
                    if self.privatekey_passphrase:
                        password = self.privatekey_passphrase.encode()
                    else:
                        password = None
                    pkey = serialization.load_pem_private_key(key_data.read(), password=password,
                                                              backend=default_backend())
            except OSError as exc:
                self.module.fail_json(msg="Failed to read private key file: {0}".format(exc))

            cert_public_key_pem = cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            private_key_public_key_pem = pkey.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            if cert_public_key_pem != private_key_public_key_pem:
                self.module.fail_json(msg="Private public bytes not matched certificate public bytes:\n {0}\n{1}\n".format(cert_public_key_pem,private_key_public_key_pem))

    def dump(self):

        result = {
            'changed': self.changed,
            'privatekey_filename': self.privatekey_filename,
            'privatekey_size': self.privatekey_size,
            'privatekey_curve': self.privatekey_curve,
            'privatekey_type': self.privatekey_type,
            'certificate_filename': self.certificate_filename,
            'chain_filename': self.chain_filename,
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
            path=dict(type='path', require=True),
            chain_path=dict(type='path', require=False),
            privatekey_path=dict(type='path', required=False),
            privatekey_type=dict(type='str', required=False),
            privatekey_size=dict(type='int', required=False),
            privatekey_curve=dict(type='str', required=False),
            privatekey_passphrase=dict(type='str', no_log=True),
            signature_algorithms=dict(type='list', elements='str'),
            alt_name=dict(type='list', aliases=['subjectAltName'], elements='str'),
            common_name=dict(aliases=['CN', 'commonName'], type='str', required=True),
            chain_option=dict(type='str', required=False, default='last'),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )

    vcert = VCertificate(module)
    vcert.ping()
    # TODO: make a following choice:
    """
    1. If certificate is present and renew is true validate it
    2. If certificate not present renew it
    3. If it present and renew is false just keep it.
    """
    vcert.enroll()
    result = vcert.dump()
    vcert.check()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
