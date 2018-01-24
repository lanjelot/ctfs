# csaw-ctf-2016-quals broken box
# fault attack on textbook RSA signing (not RSA-CRT)

import ast
from sock import Sock
from libnum import *
 
N = 172794691472052891606123026873804908828041669691609575879218839103312725575539274510146072314972595103514205266417760425399021924101213043476074946787797027000946594352073829975780001500365774553488470967261307428366461433441594196630494834260653022238045540839300190444686046016894356383749066966416917513737
E = 0x10001
sig_correct = 22611972523744021864587913335128267927131958989869436027132656215690137049354670157725347739806657939727131080334523442608301044203758495053729468914668456929675330095440863887793747492226635650004672037267053895026217814873840360359669071507380945368109861731705751166864109227011643600107409036145468092331
C = int(open("flag.enc").read())
 
f = Sock("crypto.chal.csaw.io 8002")
f.send_line("2")
f.read_until("no")
 
def sign(val):
    f.send_line("yes")
    f.send_line("%d" % val)
    sig, mod = map(int, f.read_until_re(r"signature:(\d+), N:(\d+)\s").groups())
    assert mod == N
    return sig
 
try:
    bits, vals = ast.literal_eval(open("dump").read())
except:
    bits, vals = {}, []
vals = set(vals)
 
print len(bits), "known bits"
num = 2
 
gs = {
    num * pow(num, (1 << e) * E, N) % N
    : e for e in xrange(0, 1030)
}
gsi = {
    (num * invmod(pow(num, (1 << e) * E, N), N)) % N
    : e for e in xrange(0, 1030)
}
 
while 1:
    if len(bits) >= 1024:
        print len(bits), "known", set(range(1025)) - set(bits), "unknown"
        d = sum(1 << e for e, b in bits.items() if b)
        print "Try:", `n2s(pow(C, d, N))`
 
    sig = sign(num)
    if sig in vals:
        continue
    vals.add(sig)
    test = pow(sig, E, N)
    if test in gs:
        bits[gs[test]] = 0
        print "bit[%d] = 0" % gs[test]
    if test in gsi:
        bits[gsi[test]] = 1
        print "bit[%d] = 1" % gsi[test]
    open("dump","w").write(`(bits, list(vals))`)
    print len(bits), "known bits"
