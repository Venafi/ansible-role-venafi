import unittest
import shutil
from collections import namedtuple, defaultdict
from library.venafi_certificate import VCertificate
from ansible.module_utils._text import to_bytes

testAsset = namedtuple("testAssert", "is_valid cert chain private_key password common_name")

CERT_PATH = "/tmp/cert.pem"
CHAIN_PATH = "/tmp/chain.pem"
PRIV_PATH = "/tmp/priv.pem"

class Fail(Exception):
    pass

class FakeModule(object):
    def __init__(self, asset):
        self.fail_code = None
        self.exit_code = None
        self.params = defaultdict(lambda: None)
        self.params["cert_path"] = CERT_PATH
        self.params["chain_path"] = CHAIN_PATH
        self.params["privatekey_path"] = PRIV_PATH
        self.params["common_name"] = asset.common_name
        self.params["before_expired_hours"] = 72

    def exit_json(self, **kwargs):
        self.exit_code = kwargs

    def fail_json(self, **kwargs):
        self.fail_code = kwargs
        raise Fail


class TestVcertificate(unittest.TestCase):
    def test_validate(self):
        for asset in TEST_ASSETS:
            create_testfiles(asset)
            module = FakeModule(asset)
            vcert = VCertificate(module)
            if asset.is_valid:
                self.assertIsNone(module.fail_code)
            else:
                self.assertRaises(Fail, vcert.validate)


def create_testfiles(asset):
    """
    :param testAsset asset:
    """
    for p, v in ((CERT_PATH, asset.cert), (CHAIN_PATH, asset.chain), (PRIV_PATH, asset.private_key)):

        shutil.copy("assets/" + v, p)


TEST_ASSETS = [
    testAsset(is_valid=True,  cert="valid_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem", private_key="valid_rsa2048_key.pem", password=None, common_name="test111.venafi.example.com"),
    testAsset(is_valid=False, cert="valid_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem", private_key="valid_rsa2048_key.pem", password=None, common_name="test1111.venafi.example.com"),
    testAsset(is_valid=False, cert="invalid_cert.pem", chain="valid_rsa2048_chain.pem", private_key="valid_rsa2048_key.pem", password=None, common_name="test111.venafi.example.com"),
    testAsset(is_valid=False, cert="invalid_cn_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem", private_key="valid_rsa2048_key.pem", password=None, common_name="test111.venafi.example.com"),
    testAsset(is_valid=False, cert="valid_rsa2048_cert.pem", chain="valid_rsa2048_chain.pem", private_key="valid_ec_key.pem", password=None, common_name="test1111.venafi.example.com"),
]

