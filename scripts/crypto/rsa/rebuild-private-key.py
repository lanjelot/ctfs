#!/usr/bin/python2
# https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/

import pyasn1.codec.der.encoder  
import pyasn1.type.univ  
import base64

def recover_key(p, q, e, output_file):  
    """Recoveres a RSA private key from:
        p: Prime p 
        q: Prime q
        e: Public exponent 
        output_file: File to write PEM-encoded private key to"""

    # SRC: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    def egcd(a, b):
        x,y, u,v = 0,1, 1,0
        while a != 0:
            q, r = b//a, b%a
            m, n = x-u*q, y-v*q
            b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
        return gcd, x, y

    def modinv(a, m):
        gcd, x, y = egcd(a, m)
        if gcd != 1:
            return None  # modular inverse does not exist
        else:
            return x % m

    # SRC: http://crypto.stackexchange.com/questions/25498/how-to-create-a-pem-file-for-storing-an-rsa-key/25499#25499
    def pempriv(n, e, d, p, q, dP, dQ, qInv):
        template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
        seq = pyasn1.type.univ.Sequence()
        for x in [0, n, e, d, p, q, dP, dQ, qInv]:
            seq.setComponentByPosition(len(seq), pyasn1.type.univ.Integer(x))
        der = pyasn1.codec.der.encoder.encode(seq)
        return template.format(base64.encodestring(der).decode('ascii'))

    n = p * q
    phi = (p -1)*(q-1)
    d = modinv(e, phi)
    dp = d % p
    dq = d % q
    qi = pow(q, p - 2, p)

    key = pempriv(n, e, d, p, q, dp, dq, qi)

    f = open(output_file,"w")
    f.write(key)
    f.close()
