# hack-you-2014 cryptonet 

from scapy.all import *  
from struct import *  
import zlib  
from operator import mod
from functools import reduce

def eea(a,b):  
    """Extended Euclidean Algorithm for GCD"""
    v1 = [a,1,0]
    v2 = [b,0,1]
    while v2[0]<>0:
       p = v1[0]//v2[0] # floor division
       v2, v1 = map(lambda x, y: x-y,v1,[p*vi for vi in v2]), v2
    return v1

def inverse(m,k):  
     """
     Return b such that b*m mod k = 1, or 0 if no solution
     """
     v = eea(m,k)
     return (v[0]==1)*(v[1] % k)

def crt(ml,al):  
     """
     Chinese Remainder Theorem:
     ms = list of pairwise relatively prime integers
     as = remainders when x is divided by ms
     (ai is 'each in as', mi 'each in ms')

     The solution for x modulo M (M = product of ms) will be:
     x = a1*M1*y1 + a2*M2*y2 + ... + ar*Mr*yr (mod M),
     where Mi = M/mi and yi = (Mi)^-1 (mod mi) for 1 <= i <= r.
     """

     M  = reduce(lambda x, y: x*y,ml)        # multiply ml together
     Ms = [M/mi for mi in ml]   # list of all M/mi
     ys = [inverse(Mi, mi) for Mi,mi in zip(Ms,ml)] # uses inverse,eea
     return reduce(lambda x, y: x+y,[ai*Mi*yi for ai,Mi,yi in zip(al,Ms,ys)]) % M

def root(x,n):  
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

pkts = PcapReader("packets.pcap")  
modulos = []  
remainders = []  
exponents = []  
for p in pkts:  
    pkt = p.payload
    if pkt.getlayer(Raw):
        raw = pkt.getlayer(Raw).load
        if str(pkt.sport) == "4919":
            elength = struct.unpack("!H",raw[0:2])[0]
            ezip = raw[2:2 + elength]
            e = int(zlib.decompress(ezip))
            nlength = struct.unpack("!H",raw[elength + 2 :elength + 4])[0]
            nzip =  raw[elength + 4:elength + 4 + nlength]
            n = int(zlib.decompress(nzip))
            modulos.append(n)
            exponents.append(e)
        if str(pkt.dport) == "4919":
            flaglength = struct.unpack("!H",raw[0:2])[0]
            flagzip = raw[2:2 + flaglength]
            encflag = int(zlib.decompress(flagzip))
            remainders.append(encflag)

F = crt(modulos,remainders)  
intflag = root(F,17)  
flag = hex(intflag)[2:-1].decode('hex')  
print flag  
