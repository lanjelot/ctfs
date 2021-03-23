# union-ctf-2021 babycrypto3
# https://hackmd.io/@stypr233/linectf#babycrypto3
#
# yafu.exe "factor(318..337)" -v -threads 12
 
from Crypto.Util.number import *

N = 0x0328b14139a2e54b88a4662f1a67cc3acd1929c9b62794bb64916aff02991f80456e4d0eed4d591df7708d5af2e9b4fb5689
p = 109249057662947381148470526527596255527988598887891132224092529799478353198637
q = 291664785919250248097148750343149685985101
e = 0x10001

filedata = b'\x01\x14\x1fUxa\xaa\xb3C\x9b\xe1\xeb\x87\xa0\x12`\x156e\x8a\x05\xf4\xf3x\xf7\xb9\xda\xe5J\x08Cn\\C]V\xdd\x1bH\x96\xb74\xae\xcd\x83\x88A\xd5\x92&' # ciphertext.txt
enc = int.from_bytes(filedata, 'big')

d = inverse(e, (p - 1) * (q - 1))

flag = pow(enc, d, N).to_bytes(100, 'big')
print(flag)
