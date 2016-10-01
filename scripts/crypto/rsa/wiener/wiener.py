# bctf-2015 warmup
# https://github.com/pablocelayes/rsa-wiener-attack

import ContinuedFractions, Arithmetic
import time
import sys

sys.setrecursionlimit(100000)

def wiener(e,n):
    time.sleep(1)
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    
    for (k,d) in convergents:
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            discr = s*s - 4*n
            if(discr>=0):
                t = Arithmetic.is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    return d

n = 0x9C2F6505899120906E5AFBD755C92FEC429FBA194466F06AAE484FA33CABA720205E94CE9BF5AA527224916D1852AE07915FBC6A3A52045857E0A1224C72A360C01C0CEF388F1693A746D5AFBF318C0ABF027661ACAB54E0290DFA21C3616A498210E2578121D7C23877429331D428D756B957EB41ECAB1EAAD87018C6EA3445
e = 0x466A169E8C14AC89F39B5B0357EFFC3E2139F9B19E28C1E299F18B54952A07A932BA5CA9F4B93B3EAA5A12C4856981EE1A31A5B47A0068FF081FA3C8C2C546FEAA3619FD6EC7DD71C9A2E75F1301EC935F7A5B744A73DF34D21C47592E149074A3CCEF749ECE475E3B6B0C8EECAC7C55290FF148E9A29DB8480CFE2A57801275
#c = int(open('encrypted.bin', 'rb').read().encode('hex'), 16)
c = 0x6ce2062b5986956358cbecf09e1de2fea13600532f42be838ab102014c5fd4d0c62a472c918e29c788cc27b9abc4c28894c625e3cbed8de80d31c8d483992fe9c2aba39e49fe9f1b58de1bd5c79d9588b050974261fec74fb4fa1a9050d285c200fd988aeb507b1128c8520806210cafa73f8c33e62614ff767478e4829d1017

d = wiener(e, n)
print 'found d: %r' % d

m = pow(c, d, n)
print 'm: %d %s' % (m, ('%x' % m).decode('hex'))
