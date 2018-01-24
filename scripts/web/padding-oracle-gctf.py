# google-ctf-2016 wolf spider
from cryptopal import PaddingException, PaddingOracle # https://github.com/lanjelot/cryptopal
from base64 import b64encode, b64decode
from urllib import quote, unquote
from hashlib import md5
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def flipit():
    base = ''
    def submit(ct):
        return requests.get('http://blah/view/deadbeefcafedeadbeefcafe04030201%s' % ct.encode('hex'))

    r = submit(base)
    h = md5(r.content).hexdigest()
    print 'xxx %d %d %s' % (r.status_code, len(r.content), h)

    for i, r in byteflip(base, submit):
        print '%3d %d %d %s' % (i, r.status_code, len(r.content), h)

from cookielib import DefaultCookiePolicy
class CustomCookiePolicy(DefaultCookiePolicy):
    def __init__(self, accepted_cookies):
        self.accepted_cookies = accepted_cookies
        DefaultCookiePolicy.__init__(self)

    def set_ok(self, cookie, request):
        if cookie.name in self.accepted_cookies:
            return DefaultCookiePolicy.set_ok(self, cookie, request)
        else:
            return False

PROXIES = {}#'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        PaddingOracle.__init__(self, **kwargs)
        self.session = requests.Session()
        self.session.proxies = PROXIES
        self.session.verify = False
        self.session.cookies.set_policy(CustomCookiePolicy([]))

    def oracle(self, data, **kwargs):
        ct = str(data).encode('hex')
        url = 'https://wolf-spider.ctfcompetition.com/qwerty'
        cookies = {'UID': 'b6fa37b734fe0fe603ea8f6c326bf4d92abda1c1.' + ct}

        r = self.session.get(url, cookies=cookies)
        logging.info('%s %d %d %d %.3f' % (ct.encode('hex'), r.status_code, len(str(r.headers)), len(r.content), r.elapsed.total_seconds()))
        
        if r.status_code == 500:
            raise PaddingException

if __name__ == '__main__':
    import logging
    import sys

    logging.basicConfig(format='%(threadName)s %(levelname)7s - %(message)s', level=logging.DEBUG)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)

    padbuster = PadBuster()

    if sys.argv[1] == 'encrypt':

        payload = '757365726e616d653d70696d707380000000000000000000000000000000017026757365726e616d653d61646d696e'.decode('hex')

        iv = '3a57f1a4662f38f0d64552571bdd6850'.decode('hex')
        encrypted = padbuster.encrypt(payload, block_size=16)
        print 'encrypted: %r' % encrypted

    else:
        ct = '3a57f1a4662f38f0d64552571bdd68506dd90a8056a979b1278eae82a8ad42f1'.decode('hex')
        print('Original cipher: %r' % ct)

        pt = padbuster.decrypt(ct, block_size=16)
        print('Decrypted cipher: %r' % pt)
