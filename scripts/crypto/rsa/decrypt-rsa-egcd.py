# internetwache-ctf-2016 weak rsa keys
# RSA decryption by recovering d using egcd

from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64

def egcd(a, b):
    u, u1 = 1, 0
    v, v1 = 0, 1
    while b:
        q = a // b
        u, u1 = u1, u - q * u1
        v, v1 = v1, v - q * v1
        a, b = b, a - q * b
    return a, u, v

def decrypt(p, q, e, n, ct):
    phi = (p - 1) * (q - 1)
    gcd, a, b = egcd(e, phi)
    d = a
    if d < 0:
        d += phi
    pt = pow(ct, d, n)
    return long_to_bytes(pt)

m1 = base64.b64decode('DK9dt2MTybMqRz/N2RUMq2qauvqFIOnQ89mLjXY=')
m2 = base64.b64decode('AK/WPYsK5ECFsupuW98bCFKYUApgrQ6LTcm3KxY=')
m3 = base64.b64decode('CiLSeTUCCKkyNf8NVnifGKKS2FJ7VnWKnEdygXY=')

p = 20016431322579245244930631426505729
q = 17963604736595708916714953362445519
e = 65537
n = 0xD564B978F9D233504958EED8B744373281ED1418B29F1ECFA8093D8CF
print '%r' % decrypt(p, q, e, n, bytes_to_long(m1))

p = 16549930833331357120312254608496323
q = 16514150337068782027309734859141427
e = 65537
n = 0xA23370E7D0FB00232164AC6D642840FC54E9202433F927A60EB5ADBD9
print '%r' % decrypt(p, q, e, n, bytes_to_long(m3))

p = 19193025210159847056853811703017693
q = 17357677172158834256725194757225793
e = 65537
n = 0xC5B69E1979E541F85DACDE2AA14D2722A846F41B3DB83E667E3B3D11D
print '%r' % decrypt(p, q, e, n, bytes_to_long(m2))
