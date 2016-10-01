# volga-ctf-quals-2016 lazy
# DSA with k reuse (same r in both provided signatures)
# we can therefore recover the private key

import socket
import itertools
import re
from hashlib import sha1
from server import *

p, q, g, y = import_public_key('.')
r1, s1 = import_cmd_signature('exit', '.')
r2, s2 = import_cmd_signature('leave', '.')

# recover k & x due to the same k being used for the two signatures
k = (SHA1('exit') - SHA1('leave')) * invert((s1 - s2), q)
x = (s1 * k - SHA1('exit')) * invert(r1, q) % q

sock = socket.create_connection(('lazy.2016.volgactf.ru', 8889))

challenge = read_message(sock)
print 'challenge: %r' % challenge

proof_len, proof = re.search('len\(x\)==(\d+) and x\[:\d+\]==(.+)$', challenge).groups()
print 'proof_len=%s len(proof)=%d proof=%s' % (proof_len, len(proof), proof)

for prod in itertools.product(itertools.imap(chr, range(256)), repeat=(int(proof_len) - len(proof))):
  candidate = proof + ''.join(prod)
  h = sha1(candidate).digest()
  if h[-3:] == '\xff\xff\xff':
    break

print 'solved challenge with: %r' % candidate
send_message(sock, candidate)

while True:
  cmd = raw_input('$ ')
  r, s = sign(cmd, p, q, g, x, k)
  send_message(sock, '%s\n%s\n%s' % (r, s, cmd))
  print '%r' % read_message(sock)

'''
$ python client.py 
challenge: "Solve a puzzle first: find an x such that SHA1(x)[-3:]=='\\xff\\xff\\xff' and len(x)==21 and x[:16]==uVAMSGsHPiGUvR6v"
proof_len=21 len(proof)=16 proof=uVAMSGsHPiGUvR6v
solved challenge with: 'uVAMSGsHPiGUvR6v\x00\x00\x86\xa1\x89'
$ ls
'exit.sig\nflag.txt\nkey.private\nkey.public\nleave.sig\nserver.py\n'
$ cat flag.txt
'VolgaCTF{Do_not_be_lazy_use_nonce_only_once}'
'''
