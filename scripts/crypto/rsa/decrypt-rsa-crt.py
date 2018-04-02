# camsctf-2016 one zero zero
# RSA decryption using the Chinese Remainder Theorem 

p = 0x19fbd41d69aa3d86009a967db3379c63cd501f24f7
q = 0x1b6f141f98eeb619bc0360220160a5f75ea07cdf1d
e = 65537

import gmpy2
dp = gmpy2.invert(e, (p-1)) # 0x19a817e2931b8e746ad43a151489acdabf38860831
dq = gmpy2.invert(e, (q-1)) # 0x7d889c1cba4219254920691532187f5aa2b6deb05
qinv = gmpy2.invert(q, p) # 0xaaa636b836bd372367cdf086c55ad88cd7c61e751

def decrypt(c):
  m1 = pow(c, dp, p)
  m2 = pow(c, dq, q)
  h = (qinv * (m1 - m2)) % p 
  m = m2 + h * q
  return long_to_bytes(m)

import sys
import os
from Crypto.Util.number import long_to_bytes

texts = [''] * 16
for f in sys.argv[1:]:
  c = int(open(f).read().encode('hex'), 16)
  m = decrypt(c)
  texts[int(os.path.basename(f)[:-4])-1] = m
  print '%s: %r' % (f, m)
print ''.join([text for text in texts])
