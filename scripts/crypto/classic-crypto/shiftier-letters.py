# needs to be run on the shell server due to time troubles
import telnetlib
import subprocess
import re
import sys
sys.path.append('/home/TheGoonies/shiftier/Caesar-Cipher') # https://github.com/RobSpectre/Caesar-Cipher.git
def crack_caesar(cipher):
  charset = 'abcdefghijklmnopqrstuvwxyz'
  def rot(cipher, shift):
    trans = charset[shift:] + charset[:shift]
    plaintext = ''
    for c in cipher:
      p = charset.find(c)
      if p == -1:
        plaintext += c
      else:
        plaintext += trans[p]
    return plaintext

  from caesarcipher import CaesarCipher
  results = []
  for i in range(0, len(charset)):
    plain = rot(cipher, i)
    entropy = CaesarCipher().calculate_entropy(plain)
    results.append((entropy, plain))
  bestscore, plaintext = sorted(results)[0]
  return plaintext

t = telnetlib.Telnet('web.lasactf.com', 4056)
for i in range(128):
  c = t.read_until('\n').rstrip()
  print '%2d c: %r' % (i, c)
  if 'lasactf{' in c:
    break
  p = crack_caesar(c)
  print '%2d p: %r' % (i, p)
  t.write(p + '\n')
