#!/usr/bin/env python

import os
import sys
import logging

#sys.path.append(os.path.expanduser('~/tools/crypto/Caesar-Cipher'))
sys.path.append(os.path.expanduser('~/tools/crypto/vigenere'))

#from caesarcipher import CaesarCipher
from pygenere import *
from pwn import *
# https://pwntools.readthedocs.org/en/2.2/tubes.html#module-pwnlib.tubes.process

import re
import subprocess

def get_cipher(data):
  return re.search('psifer text: (.+)$', data, re.M).group(1)

with context.local(log_level='INFO'):

  conn = remote('192.168.122.132', 12345)
  data = conn.clean()
  caesar = get_cipher(data)
  print '[*] got caesar: %r' % caesar

  #cracked = CaesarCipher(caesar).cracked
  cracked = VigCrack(caesar).crack_message(1)
  print '[+] cracked: %r' % cracked

  answer = re.search('the answer to this stage is (\S+)', cracked).group(1)
  conn.send('%s\n' % answer)

  data = conn.clean()
  scytale = get_cipher(data)
  print '[+] got scytale: %r' % scytale

  cmd = ['python', os.path.expanduser('~/code/python/bf-transposition-scytale.py')]

  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  out, err = p.communicate(scytale)

  for c in out.splitlines():
    if 'It should be fairly straight forward if you have done lots of basic crypto' in c:
      print '[+] cracked: %r' % c
      answer = re.search('The magic phrase for your efforts is "(.+?)"', c).group(1)
      break

  conn.send('%s\n' % answer)
  data = conn.clean()
  vige = get_cipher(data)
  print '[+] got vigenere: %r' % vige

  cracked = ''.join(VigCrack(vige).crack_message().split(' '))
  print '[+] cracked: %r' % cracked

  answer = re.search('RIGHTHERE(.+?)OKNOWMORE', cracked).group(1)
  conn.send('%s\n' % answer)
  data = conn.clean_and_log()
