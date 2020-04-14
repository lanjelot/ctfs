# code stolen from https://www.reddit.com/r/securityCTF/comments/46pokl/decrypt_rsa_if_public_exponent_is_wrong_e3/

ciphertext = 11623094406793268154338542114083156484004409737976158320847125127716353187390719965404367829601557351107397441930760491465288237620341417119341208833785489855135738325672921463322561674709779377308398349965271739917501573280587887164590881898122161644193610351940064304786909957435164044577350120369830884811143344008280460456813338403266028851424044715624674994833292593456200312734695296045719592467095819302321167941468882377421041382464913094344200772143467655263803282888947948944826836928419495631864944678992516353561049073202658423070569946648167920683574605957886986368975391404298306620165549596621421812576L

n = """00:af:78:89:ed:57:22:2e:a3:23:d9:b2:fb:5c:01:
    fb:db:7c:7a:27:17:d2:8e:bb:97:1d:76:cb:71:7b:
    0f:12:15:07:2d:9b:ac:34:55:91:e7:d8:3c:08:3a:
    58:74:c3:32:2e:59:2e:8f:26:c2:46:c9:5b:26:b2:
    88:3a:5f:c0:6e:39:62:ef:79:c0:71:f4:55:1d:4d:
    7b:6c:ba:87:e4:5c:22:9c:c4:0e:7e:0b:5e:63:b4:
    20:5e:8b:1e:0b:b8:d4:3a:cf:3a:e3:56:e3:3b:5f:
    c1:ef:dd:e9:92:bf:ab:f1:ba:49:57:17:f8:32:7e:
    35:60:2e:ec:18:f9:98:d1:0a:ef:94:7c:ee:29:61:
    04:2e:1f:92:0c:d8:90:d0:35:8e:d1:0b:86:a5:c8:
    14:55:ec:ff:00:2a:0b:d2:22:1e:cb:06:d6:9d:1d:
    bf:56:3c:cb:c6:84:e6:ab:d3:81:01:7f:0c:11:6a:
    7e:81:4b:6c:1d:89:22:5c:c3:a5:6c:31:38:6c:5d:
    97:28:ab:99:55:e2:17:e0:1c:99:03:60:6e:05:37:
    c4:21:77:f6:a5:f4:50:47:38:96:56:4f:cc:05:92:
    31:7f:03:ba:63:56:98:48:ee:28:c7:7f:ac:7a:52:
    c0:f2:f7:91:14:c7:19:7c:16:e7:dd:21:5f:48:f9:
    76:d1""".replace(' ','').replace(':','').replace('\n','').strip()
n = long(n ,16)

import sys
ciphertext = long(sys.argv[1])
n = long(sys.argv[2])

print 'ciphertext: %r' % ciphertext
print 'n: %r' % n

import math
print 'size of ciphertext', math.log(ciphertext, 2)
print 'size of n', math.log(n, 2)

assert(ciphertext < n)

# https://stackoverflow.com/questions/15978781/how-to-find-integer-nth-roots
# or see gmpy2.iroot()
def iroot(k, n):
    hi = 1
    while pow(hi, k) < n:
        hi *= 2
    lo = hi / 2
    while hi - lo > 1:
        mid = (lo + hi) // 2
        midToK = pow(mid, k)
        if midToK < n:
            lo = mid
        elif n < midToK:
            hi = mid
        else:
            return mid
    if pow(hi, k) == n:
        return hi
    else:
        return lo

assert(iroot(55, 28937**55) == 28937)
assert(iroot(55, 28937**55 + 3) == 28937)

c2 = ciphertext
while True:
  root = iroot(3, c2)
  rooth = hex(root)[2:-1]
  if len(rooth) % 2:
    rooth = '0' + rooth
  plaintext = rooth.decode('hex')
  if 'flag' in plaintext or root**3 == c2:
    print 'it worked!'
    print plaintext
    print root
    print c2
  c2 += n
