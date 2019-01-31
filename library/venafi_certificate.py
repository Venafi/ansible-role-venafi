#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function, unicode_literals
import time
import datetime
import os.path
import random
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_text

HAS_VCERT = HAS_CRYPTOGRAPHY = True
try:
    from vcert import CertificateRequest, Connection
except ImportError:
    HAS_VCERT = False
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import serialization, hashes
except ImportError:
    HAS_CRYPTOGRAPHY = False

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
            - Try to renew certificate if is existing but not valid.

    cert_path:
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
            - Path to the private key to use when signing the certificate signing request. If not set will be placed 
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
            - Curves name for ECDSA algorithm. Choices are "P224", "P256", "P384", "P521".

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
      cert_path: '/tmp'
    register: testout
  - name: dump test output
    debug:
      msg: '{{ testout }}'

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
      cert_path: '/tmp'
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


class VCertificate:
    def __init__(self, module):
        """
        :param AnsibleModule module:
        """
        self.common_name = module.params['common_name']

        self.test_mode = module.params['test_mode']
        self.url = module.params['url']
        self.password = module.params['password']
        self.token = module.params['token']
        self.user = module.params['user']
        self.zone = module.params['zone']
        self.privatekey_filename = module.params['privatekey_path']
        self.certificate_filename = module.params['cert_path']
        self.privatekey_type = module.params['privatekey_type']
        self.privatekey_curve = module.params['privatekey_curve']
        self.privatekey_size = module.params['privatekey_size']
        self.privatekey_passphrase = module.params['privatekey_passphrase']
        self.chain_filename = module.params['chain_path']
        self.csr_path = module.params['csr_path']
        self.args = ""
        self.changed = False
        self.module = module
        self.ip_addresses = []
        self.email_addresses = []
        self.san_dns = []
        if module.params['alt_name']:
            for n in module.params['alt_name']:
                if n.startswith(("IP:", "IP Address:")):
                    ip = n.split(":", 1)[1]
                    self.ip_addresses.append(ip)
                elif n.startswith("DNS:"):
                    ns = n.split(":", 1)[1]
                    self.san_dns.append(ns)
                elif n.startswith("email:"):
                    mail = n.split(":", 1)[1]
                    self.email_addresses.append(mail)
                else:
                    self.module.fail_json(msg="Failed to determine extension type: {0}".format(n))
        trust_bundle = module.params['trust_bundle']
        if trust_bundle:
            self.conn = Connection(url=self.url, token=self.token, fake=self.test_mode,
                                   user=self.user, password=self.password,
                                   http_request_kwargs={"verify": trust_bundle})
        else:
            self.conn = Connection(url=self.url, token=self.token, fake=self.test_mode,
                                   user=self.user, password=self.password)
        self.before_expired_hours = module.params['before_expired_hours']

    def check_dirs_existed(self):
        cert_dir = os.path.dirname(self.certificate_filename or "/a")
        key_dir = os.path.dirname(self.privatekey_filename or "/a")
        chain_dir = os.path.dirname(self.chain_filename or "/a")
        ok = True
        for p in set((cert_dir, key_dir, chain_dir)):
            if os.path.isdir(p):
                continue
            elif os.path.exists(p):
                self.module.fail_json(msg="Path %s already exists but this is not directory." % p)
            elif not os.path.exists(p):
                self.module.fail_json(msg="Directory %s does not exists." % p)
            ok = False
        return ok

    def _check_private_key_correct(self):
        if not self.privatekey_filename:
            return None
        if not os.path.exists(self.privatekey_filename):
            return False
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
        request = CertificateRequest(
            common_name=self.common_name,
            key_password=self.privatekey_passphrase,
        )
        use_existed_key = False
        if self._check_private_key_correct():  # May be None
            private_key = to_text(open(self.privatekey_filename, "rb").read())
            request.private_key = private_key
            use_existed_key = True
        elif self.privatekey_type:
            key_type = {"RSA": "rsa", "ECDSA": "ec", "EC": "ec"}.get(self.privatekey_type)
            if not key_type:
                self.module.fail_json(msg="Failed to determine key type: {0}. Must be RSA or ECDSA".format(
                    self.privatekey_type))
            request.key_type = key_type
            request.key_curve = self.privatekey_curve
            request.key_length = self.privatekey_size

        request.ip_addresses = self.ip_addresses
        request.san_dns = self.san_dns
        request.email_addresses = self.email_addresses

        request.chain_option = self.module.params['chain_option']
        try:
            csr = open(self.csr_path, "rb").read()
            request.csr = csr
        except Exception as e:
            self.module.log(msg=str(e))
            pass

        self.conn.request_cert(request, self.zone)
        print(request.csr)
        while True:
            cert = self.conn.retrieve_cert(request)  # vcert.Certificate
            if cert:
                break
            else:
                time.sleep(5)
        if self.chain_filename:
            self._atomic_write(self.chain_filename, "\n".join(cert.chain))
            self._atomic_write(self.certificate_filename, cert.cert)
        else:
            self._atomic_write(self.certificate_filename, cert.full_chain)
        if not use_existed_key:
            self._atomic_write(self.privatekey_filename, request.private_key_pem)
        # todo: server generated private key

    def _atomic_write(self, path, content):
        suffix = ".atomic_%s" % random.randint(100, 100000)
        try:
            with open(path+suffix, "wb") as f:
                f.write(to_bytes(content))
        except OSError as e:
            self.module.fail_json(msg="Failed to write file %s: %s" % (path+suffix, e))

        self.module.atomic_move(path+suffix, path)
        self.changed = True
        self._check_and_update_permissions(path)

    def _check_and_update_permissions(self, path):
        file_args = self.module.load_file_common_arguments(self.module.params)
        file_args['path'] = path
        if self.module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    def _check_certificate_validity(self, cert):
        if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != self.common_name:
            return False
        if cert.not_valid_after - datetime.timedelta(hours=self.before_expired_hours) < datetime.datetime.now():
            return False
        if cert.not_valid_before - datetime.timedelta(hours=24) > datetime.datetime.now():
            return False
        ips = []
        dns = []
        for e in cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
            if isinstance(e, x509.general_name.DNSName):
                dns.append(e.value)
            elif isinstance(e, x509.general_name.IPAddress):
                ips.append(e.value.exploded)
        if self.ip_addresses and sorted(self.ip_addresses) != sorted(ips):
            return False
        if self.san_dns and sorted(self.san_dns) != sorted(dns):
            return False
        return True

    def _check_certificate_public_key_matched_to_private_key_file(self, cert):
        if not self.privatekey_filename:
            return True
        if not os.path.exists(self.privatekey_filename):
            return False
        try:
            with open(self.privatekey_filename, 'rb') as key_data:
                password = self.privatekey_passphrase.encode() if self.privatekey_passphrase else None
                pkey = serialization.load_pem_private_key(key_data.read(), password=password, backend=default_backend())

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
            return False
        return True

    def _check_files_permissions(self):
        files = (self.privatekey_filename, self.certificate_filename, self.chain_filename)
        return all([self._check_file_permissions(x) for x in files])

    def _check_file_permissions(self, path, update=False):
        return True  # todo: write

    def check(self):
        """Return true if running will change anything"""
        if not os.path.exists(self.certificate_filename):
            return True
        if self._check_private_key_correct() is False:  # may be None
            return True
        try:
            with open(self.certificate_filename, 'rb') as cert_data:
                cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())  # type: x509.Certificate
        except OSError as exc:
            self.module.fail_json(msg="Failed to read certificate file: {0}".format(exc))

        if not self._check_certificate_public_key_matched_to_private_key_file(cert):
            return True
        if not self._check_certificate_validity(cert):
            return True

    def validate(self):
        """Ensure the resource is in its desired state."""
        try:
            with open(self.certificate_filename, 'rb') as cert_data:
                cert = x509.load_pem_x509_certificate(cert_data.read(), default_backend())  # type: x509.Certificate
        except (OSError, ValueError)as exc:
            self.module.fail_json(msg="Failed to read certificate file: {0}".format(exc))

        if not self._check_certificate_public_key_matched_to_private_key_file(cert):
            self.module.fail_json(msg="Private public bytes not matched certificate public bytes")
        if not self._check_certificate_validity(cert):
            self.module.fail_json(msg="failing check certificate validity")
        if not self._check_private_key_correct():
            self.module.fail_json(msg="Bad private key")
        if not self._check_files_permissions():
            self.module.fail_json(msg="Bad files permissions")

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
            trust_bundle=dict(type='str', required=False),

            # General properties of a certificate
            path=dict(type='path', aliases=['cert_path'], require=True),
            chain_path=dict(type='path', require=False),
            privatekey_path=dict(type='path', required=False),
            privatekey_type=dict(type='str', required=False),
            privatekey_size=dict(type='int', required=False),
            privatekey_curve=dict(type='str', required=False),
            privatekey_passphrase=dict(type='str', no_log=True),
            alt_name=dict(type='list', aliases=['subjectAltName'], elements='str'),
            common_name=dict(aliases=['CN', 'commonName', 'common_name'], type='str', required=True),
            chain_option=dict(type='str', required=False, default='last'),
            csr_path=dict(type='path', require=False),

            # Role config
            before_expired_hours=dict(type='int', required=False, default=72)
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )
    if not HAS_VCERT:
        module.fail_json(msg='"vcert" python library is required')
    if not HAS_CRYPTOGRAPHY:
        module.fail_json(msg='"cryptography" python library is required')
    vcert = VCertificate(module)
    will_be_changed = vcert.check()
    if module.check_mode:
        module.exit_json(changed=will_be_changed)

    # TODO: make a following choice (make it after completing role @arykalin):
    """
    1. If certificate is present and renew is true validate it
    2. If certificate not present renew it
    3. If it present and renew is false just keep it.
    """
    if not vcert.check_dirs_existed():
        module.fail_json(msg="Dirs not existed")
    if will_be_changed or module.params['force']:
        vcert.enroll()
    vcert.validate()
    result = vcert.dump()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
