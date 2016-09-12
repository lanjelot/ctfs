# one zero zero - Camsctf 2016
# RSA decryption using the Chinese Remainder Theorem 

p = 0x19fbd41d69aa3d86009a967db3379c63cd501f24f7
q = 0x1b6f141f98eeb619bc0360220160a5f75ea07cdf1d

dp = 0x19a817e2931b8e746ad43a151489acdabf38860831
dq = 0x7d889c1cba4219254920691532187f5aa2b6deb05

qinv = 0xaaa636b836bd372367cdf086c55ad88cd7c61e751

def decrypt(c):
  m1 = pow(c, dp, p)
  m2 = pow(c, dq, q)
  h = (qinv * (m1 - m2)) % p 
  m = m2 + h * q
  return m

def decode(m):
  s = '%x' % m
  s = s if len(s) % 2 == 0 else '0' + s
  return s.decode('hex')

import sys
import os
texts = [''] * 16
for f in sys.argv[1:]:
  c = int(open(f).read().encode('hex'), 16)
  m = decrypt(c)
  texts[int(os.path.basename(f)[:-4])-1] = decode(m)
  print '%s: %r' % (f, decode(m))
print ''.join([text for text in texts])
