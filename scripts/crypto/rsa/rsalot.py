#!/usr/bin/python
#
# Backdoor CTF 2015
# RSALOT (CRYPTO/250) Exploit
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

# adapted for pragyan-ctf-2016 rsaq (where q was the common factor and not p)

# see common-factors.py for a simpler alternative to commonPrimeFactor()

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

# GCD (times sign of b if b is nonzero, times sign of a if b is zero)
def gcd(a,b):
  while b != 0:
      a, b = b, a % b
  return a

# Extended Greatest Common Divisor
def egcd(a, b):
  if (a == 0):
      return (b, 0, 1)
  else:
      g, y, x = egcd(b % a, a)
      return (g, x - (b // a) * y, y)

# Modular multiplicative inverse
def modInv(a, m):
  g, x, y = egcd(a, m)
  if (g != 1):
      raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
  else:
      return x % m

# Calculate private exponent from n, e, p, q
def getPrivate(n, e, p, q):
  d = modInv(e, (p-1)*(q-1))
  return RSA.construct((n, e, d, p, q, ))

# Get prime factors of n1 if n1 and n2 have common prime factor
def commonPrimeFactor2(n1, n2):
  p = gcd(n1, n2)
  if((p != 1) and (p != n1) and (p != n2)):
      q = n1 / p
      return (p, q)
  else:
      return None

def commonPrimeFactor(n1, n2):
  q = gcd(n1, n2)
  if((q != 1) and (q != n1) and (q != n2)):
      p = n1 / q
      return (p, q)
  else:
      return None

# Import all keys
def getKeys():
  keys = {}
  privKeys = []

  filenames = next(os.walk("."))[2]
  for filename in filenames:
      if(filename[-3:] == "pem"):
          f = open(filename, 'rb')
          externKey = f.read()
          f.close()
          keys[int(filename[-5])] = RSA.importKey(externKey)

  # Check for common prime factors
  for index1 in keys: 
      key1 = keys[index1]

      for index2 in keys:
          if(index1 == index2):
              continue

          key2 = keys[index2]
          r = commonPrimeFactor(key1.n, key2.n)
          if(r != None):
              print "[+]Got private key from common modulus between (%d) and (%d)" % (index1, index2)
              p, q = r
              print 'p=', p
              print 'q=', q
              privKeys.append(getPrivate(key1.n, key1.e, r[0], r[1]))

  return privKeys

# Decrypt ciphertext using private key (PKCS1 OAEP format)
def do_decrypt(rsakey, ciphertext):
  rsakey = PKCS1_OAEP.new(rsakey) 
  plaintext = rsakey.decrypt(b64decode(ciphertext)) 
  return plaintext

# Get all private keys
privKeys = getKeys()
print 'privKeys: %r' % privKeys
ciphertext = open("ciphertext.txt", 'rb').read()

print do_decrypt(privKeys[0], ciphertext)
exit(0)

# Try all potential private keys we obtain
for privKey in privKeys:
  try:
      print do_decrypt(privKey, ciphertext)
      print ""
  except:
      pass
