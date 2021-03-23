# nahamcon-ctf-2021 elliptical
# nonce re-use
# https://ctftime.org/writeup/26445

from Crypto.Util.number import *
import requests, base64, hashlib
from fastecdsa import ecdsa
from fastecdsa.curve import P256

def auth(user):
    session = requests.Session()
    response = session.post(url='http://challenge.nahamcon.com:30669/signin', data={'username':user})

    token = session.cookies.get_dict()['token']
    hashed = token.split('.')[0] + '.' + token.split('.')[1]
    signature = token.split('.')[-1]

    raw_signature = base64.b64decode(signature.replace('-', '+').replace('_','/')  + "==").hex()

    return hashed.encode(), int(raw_signature[:64], 16), int(raw_signature[64:], 16)

def modinv(a, modulus):
    return pow(a, modulus - 2, modulus)

def divmod(a, b, modulus):
    return (a * modinv(b, modulus)) % modulus

m1, r, s1 = auth('admim')
m2, r, s2 = auth('admio')

order = P256.q
z1 = int(hashlib.sha256(m1).hexdigest(), 16)
z2 = int(hashlib.sha256(m2).hexdigest(), 16)

k = divmod(z1 - z2, s1 - s2, order)
d = divmod(k * s1 - z1, r, order)
print("[+] Private key:", d)

new_token = b'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.' + base64.b64encode(b'{"username":"admin"}')
r, s = ecdsa.sign(new_token, d)
print("[+] Forged signature:", (r, s))
new_token += b"." + base64.b64encode(long_to_bytes(r) + long_to_bytes(s)).replace(b'+',b'-').replace(b'/',b'_').replace(b'=',b'')

print("[+] JWT token:", new_token.decode())
