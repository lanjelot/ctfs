import sys
from Crypto.PublicKey import RSA
from Crypto.Util.number import size

with open(sys.argv[1], 'r') if len(sys.argv) > 1 else sys.stdin as f:
    key = RSA.importKey(f.read())

print "N = %s" % key.n
print "e = %s" % key.e
print "N size is %s bits" % size(key.n)
