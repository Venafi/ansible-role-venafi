import unittest
from collections import namedtuple, defaultdict
from library.venafi_certificate import VCertificate
from ansible.module_utils._text import to_bytes

testAsset = namedtuple("testAssert", "is_valid cert chain private_key password common_name")

CERT_PATH = "/tmp/cert.pem"
CHAIN_PATH = "/tmp/chain.pem"
PRIV_PATH = "/tmp/priv.pem"



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
        self.params["test_mode"] = True

    def exit_json(self, **kwargs):
        self.exit_code = kwargs

    def fail_json(self, **kwargs):
        print(1111)
        self.fail_code = kwargs


class TestVcertificate(unittest.TestCase):
    def test_validate(self):
        for asset in TEST_ASSETS:
            create_testfiles(asset)
            module = FakeModule(asset)
            vcert = VCertificate(module)
            vcert.validate()
            self.assertIsNone(module.fail_code)




def create_testfiles(asset):
    """
    :param testAsset asset:
    """
    for p, v in ((CERT_PATH, asset.cert), (CHAIN_PATH, asset.chain), (PRIV_PATH, asset.private_key)):
        f = open(p, "wb")
        f.write(to_bytes(v))
        f.close()


TEST_ASSETS = [
    testAsset(is_valid=True,  cert="""-----BEGIN CERTIFICATE-----
MIIHBTCCBO2gAwIBAgITbQB2yTTOt8JP17HI7QAAAHbJNDANBgkqhkiG9w0BAQsF
ADBbMRMwEQYKCZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZp
MRUwEwYKCZImiZPyLGQBGRYFdmVucWExFTATBgNVBAMTDFFBIFZlbmFmaSBDQTAe
Fw0xOTAxMjgxMjAyMzNaFw0yMTAxMjcxMjAyMzNaMCUxIzAhBgNVBAMTGnRlc3Qx
MTEudmVuYWZpLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA40KBhT8rF6deSkExEW334YiwWlnpJjfzRbF6401Nm/+kVcZfG20IiNoY
17rlCcBHNx6QKBqP4N9O1mMmV0Q0FCXusvPPsJqymdfn9EJLxBSFVLlhmcuCmb10
Yw7/uY9VyVKW20Cvy1dr3SNgXTQI0sOOkm+SJPhEiFUuXnwMStvBmqFbjpx86dLC
nymwSDE8vgvUnAAk2MF6vKsfzc1qqiq0OIvV0FD12sH2Ubiq1RNKPYkzbNn382fV
LOP3+VBnUezuSy3VeWuP3a5PlBTIUaQLHw3LKv0HV9eKRsBQagMONp6S8Q+G4EAd
sdjMJqmoJG7JMU0/VY3cIUFMTZhCAwIDAQABo4IC9jCCAvIwCQYDVR0RBAIwADAd
BgNVHQ4EFgQUIFA2UfU9Kn2htZ2nobCp2UlOqWowHwYDVR0jBBgwFoAUPKycpg2h
MNRWpz14vCMb7LR7TXUwggEiBgNVHR8EggEZMIIBFTCCARGgggENoIIBCYZCaHR0
cDovL3FhdmVuYWZpY2EudmVucWEudmVuYWZpLmNvbS9DZXJ0RW5yb2xsL1FBJTIw
VmVuYWZpJTIwQ0EuY3JshoHCbGRhcDovLy9DTj1RQSUyMFZlbmFmaSUyMENBLENO
PXFhdmVuYWZpY2EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENO
PVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9dmVucWEsREM9dmVuYWZpLERD
PWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9
Y1JMRGlzdHJpYnV0aW9uUG9pbnQwggE4BggrBgEFBQcBAQSCASowggEmMGoGCCsG
AQUFBzAChl5odHRwOi8vcWF2ZW5hZmljYS52ZW5xYS52ZW5hZmkuY29tL0NlcnRF
bnJvbGwvcWF2ZW5hZmljYS52ZW5xYS52ZW5hZmkuY29tX1FBJTIwVmVuYWZpJTIw
Q0EuY3J0MIG3BggrBgEFBQcwAoaBqmxkYXA6Ly8vQ049UUElMjBWZW5hZmklMjBD
QSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMs
Q049Q29uZmlndXJhdGlvbixEQz12ZW5xYSxEQz12ZW5hZmksREM9Y29tP2NBQ2Vy
dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
MCEGCSsGAQQBgjcUAgQUHhIAVwBlAGIAUwBlAHIAdgBlAHIwCwYDVR0PBAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4ICAQBBv4wemLIT
nibcOBnYCKhkJj97i/EVcOWALXi9iVoKtVUuLFTHjLxyzwHobM8ndRJ9Ard/F9Uk
UqEsqf+9SWdZwMWTGmNTdWjywabSP508LdkSz9Ffpmz/Ysw8smbQfFPxbpxqCin8
j5QX2QHeA3+OZvX7/4fc4Xog/19skRrLR/O65IEO+gd5MZjsf3A9mvEtAJB05uiF
L1szUAeKMYFmlVkdcA6C2xxxai049sdkgUwHJ+eqbF43Ko2g6s1kfGtXZI26B5kx
Obqf3KUONRhrUA3NM6LO9A/io5oxweFjvofsFA/QuoU5y4xXzdB8bAS+FzWug/Ve
6/RT7Xw6RsCDreBFdLd+Xe5vrzq6/duHWWnBTDd23DAlTWrD3RKD16OwnJppaG31
YB0/j+O5dLOqkvh1OTNUAaxOTeE7K/X9s1aIZoeb79W26DMDKJNJJ5/djqNImylU
ZIf77mYIDX+yDCYsrXG5XzecC6HXpCEkJtBEbBuIuW/nwfiuECbiHIqMgStavZzd
2URasPdBG2vquDxDRgpXYavSgod0a/QjJ+kDXVvHEAyFyruyDcV3DXi+Tk1DcWtV
B2Axcb0wRYYfFFTWrfP74Zgse4hpKA/DHSLxQyzZ7dI2xQjowm6ugAx8K8v/FlhO
129nilQZ1FsjrhKgFp6OBNc+4ceFTOjDdA==
-----END CERTIFICATE-----
""", chain="""-----BEGIN CERTIFICATE-----
MIIFpjCCA46gAwIBAgIQPY6aY41C6JxH4BxIUMuftTANBgkqhkiG9w0BAQsFADBb
MRMwEQYKCZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZpMRUw
EwYKCZImiZPyLGQBGRYFdmVucWExFTATBgNVBAMTDFFBIFZlbmFmaSBDQTAeFw0x
NjExMjExMzU4NTVaFw0zNjExMjExNDA4NTRaMFsxEzARBgoJkiaJk/IsZAEZFgNj
b20xFjAUBgoJkiaJk/IsZAEZFgZ2ZW5hZmkxFTATBgoJkiaJk/IsZAEZFgV2ZW5x
YTEVMBMGA1UEAxMMUUEgVmVuYWZpIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEA3M53kteYHPX83uDvxd25NBNfokj4FBGXhrrAuUbiZFu2oolu9W9y
KD/7OwlivxnEkEbUcdaLvKJmlmVUqZqmPATATsvU1RVuv6P2e7BT/C9ErSPQOkUW
XkKBfZtOJufHs0FSwUa+AUm6Kd+bkOEZIbAmMNuip5aC7HDfmN77cSksXRNX/UjU
W5B5y/0aV58p32GGCySr9gBqYwYHX3pPCUl+rnf/+hEMViI1TWlLaVa77uodCfD8
b7hNopVk8KAnNlNhEYNVIQnfKC/OsNGP63FYqDswS0SRr/M6XmoMHZSr6MEXCz9m
MQLeft/nR8llcvB+CnfuzEUWWj2zgBzsCwvBZ6vUrz0ziZmUODqek9oQ+6L9HOJn
nBATIOLMYfDX0kYvfnvVnA2b4ugdrD/PpYOnKHW3twpxVJ2HplRX4dAZ2TXJs7tU
EYgAcYAJzk1rE/yBEgY0Z6Wj8WlBj7PzTxWs8NUhEvrpPNCus2ARz8Xx8IE6A9cI
87U0BRISiFFtd0BFG0EF4C6vZaBtXK049swsVu+2f2Q9mzxskcUcThxVGHqNLYBY
Zadwjq/+O8/OLG6mpu9d1TpF7TSFmFd2Mc0tqm9ROthtKXRPahVQSmXTYhSrCLRj
/GMCS2+zR6rv3y5K/YBEaskpM0/wZHygFbucjfFizgGxZbvk3NYxLP0CAwEAAaNm
MGQwEwYJKwYBBAGCNxQCBAYeBABDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFDysnKYNoTDUVqc9eLwjG+y0e011MBAGCSsGAQQBgjcV
AQQDAgEAMA0GCSqGSIb3DQEBCwUAA4ICAQDb6m9/c694TIo/V2Bowq0iei5f0TKJ
Cc0X4+jUGa3ivkQRB0EgKFbXUHtP52Pribi2OeGeLJibMDcB6sfiOjSmun83Pe8D
pOAAq+YlKRiUTF4qb8SD5iJPPTTL/KaRxisBLcUGxOvhBVJcm5rQ9crowE5RN9qm
YVGVG73T9Y+p9GgLZUz3v1YTZ89LubLfiW6x8Q8jyzjkgfKY49oxGf/DrWp9y6gt
TBFcG4pQNOC7AIVYj5UTPxZqbuuJTkwADdRwElSvzHxceHvICJaSbSNiHhX4XsrQ
FMajGG3AZC879wcPW1pejPN4A2705WPZ/8mMVuYJDadQ6Pt8+PUXJDcmKGtVv+1E
d7AVpYqhgWwze+V+eRgI5rTPr0ijFXX8VGFUcJl5JwUwPLrUNA45UMA7V5qgjb9+
k+GXaoC9l4PyiSdEm/vR0+Vbj/ZB7sgU9XlFe8D8e3c2bdvg2Iwjjx4RBQffnoWl
vc/Ofw9Hbk3LUsn7k4GOrQNpMlz14tpY3pPi6qrZFH/RabZngL5Tog9mszcqgMBv
9FyPr0ubOaCXBXJzRjVQjHV0YOGwFeLvQAohFIAdMlCVRVx+rIzupEskGgAMnKtG
QXe+VMF9FXaRqDI/cCNsBnR++USinZvwGY6SecfDtHA7x65yJol7Y8YtURNfyDfg
yVzOWlPcu2gJaw==
-----END CERTIFICATE-----
""", private_key="""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA40KBhT8rF6deSkExEW334YiwWlnpJjfzRbF6401Nm/+kVcZf
G20IiNoY17rlCcBHNx6QKBqP4N9O1mMmV0Q0FCXusvPPsJqymdfn9EJLxBSFVLlh
mcuCmb10Yw7/uY9VyVKW20Cvy1dr3SNgXTQI0sOOkm+SJPhEiFUuXnwMStvBmqFb
jpx86dLCnymwSDE8vgvUnAAk2MF6vKsfzc1qqiq0OIvV0FD12sH2Ubiq1RNKPYkz
bNn382fVLOP3+VBnUezuSy3VeWuP3a5PlBTIUaQLHw3LKv0HV9eKRsBQagMONp6S
8Q+G4EAdsdjMJqmoJG7JMU0/VY3cIUFMTZhCAwIDAQABAoIBAGrjFNf+5d2yMn7q
OpHgDv5cs9VLBIWdOyZEW3AdI6uDiV9udb0Ig0MakSSmGqODc/tQvKygEZvKa+IZ
sCbLRVNUo/g3BDAkEmyZR9dydwA6RpuatXUIaty0ZtFQdKZp7AdMePeWbRhOfcT8
po4vsxauM5hcMXiB7HnS1oRKA94Qqw+UpN3zsy1LupkkWX2URLKDzMnTQwVr85uq
qma+FnLASq2Zdh+nkInQ7rqGPlFFp7kltMRo/bvJJ6V3RzytK6wfwq/Px2H+Vv/h
TVXghml1+drBf7bhjVsMJwVEAvOTfFmucb/cKfXyx/1S8+zAtin8GoIUlMEv1KA1
vvHMTwECgYEA82Ud+2oYx7cFQm/g7pX4fwyBOxcKiShGLNx9lQ0EVvMNrUAopIu2
DMH9XSphtgxPxZrotv6kYvXaejWG8MaDS2W79HwJhz6tLYTvslLZFcug8I91oMQZ
vPKrMtPudBX6xDFUrhHJrDNp2TW2KeLEDqTNDwq/991A26HDjwqEBnMCgYEA7wd4
tTuhqeUkNUOwyFMHfR9MjIQ6ZsvMOMAZ0ymxYXH1P/6qQRJk9U+A9L+EMi4v8VgI
wB33X+4lnH1AnlIPBDEyHX3t9oL8GayXb9DD3ga9YPuq0LPRHehRERMvV6XEyPKp
aKPkK3NkVkpYkvxu+hUbWDsGA3O+oq6UIx75YjECgYEAg556yCpnnBhsz7CQgnS3
HH02pS2glOsih7/0aVXQsvRcwQOg9tpWaC+/Q1JX5Ipj2QgcMFkjrCAnNU8c2bd/
6JXrPhqVTH2oSKVKubPzkMW9ElmB0p45DORtj97rY/s+0DmdAUS9OlHTO5LAH4Zx
XznfafL2PKN5H0wq5H9bReECgYBkTYFUo8JSFcqc41vSpCzXT4QCzxXmvwxioBH2
L1+04WolwYrWJY7h9cvKaHdjy0fpAaUiYTDGO5vi0BiGly6f9rjt8UMjF5IMgAVI
MZWPnMppYRIr49kTsMIb5S4PnIs4O8PlGikMJq7rGuWSQIWdQbAo1RPP7QkJITMe
jcfecQKBgQCiuvGRQwBXKUPvf7mqrG7Sj0ICNW0GYBg6FmO7SZe5iUWNXkDUg82g
7nEXtET1D55Tmzvlt6L4G1JDenapZb571aQ9ggpqnt+2ArQs9V+amYElZBTTBtSt
RQO19J2gity7TvO4qSoDlIpDra5u2zJupqSaT6ks5IUVmgPXHz5vzQ==
-----END RSA PRIVATE KEY-----
""", password=None, common_name="test111.venafi.example.com"),

]



