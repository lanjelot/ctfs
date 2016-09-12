# ndh-quals-2016 invest

from scapy.all import *
from scapy.layers import http
from base64 import b64decode
import zlib

def chunk(s, bs):
  return [s[i:i + bs] for i in range(0, len(s), bs)]

pcap = rdpcap('invest.pcap') # or PcapReader('invest.pcap')?
encrypted = {}

for p in pcap:
  if p.haslayer(http.HTTPRequest):
    r = p.getlayer(http.HTTPRequest)
    ack = p.getlayer(TCP).ack
    path = r.Path

  elif p.haslayer(http.HTTPResponse):
    if p.getlayer(TCP).seq != ack:
      continue
    r = p.getlayer(http.HTTPResponse)
    if r.fields.get('Content-Encoding', '') == 'gzip':
      data = zlib.decompress(r.payload.load, 16 + zlib.MAX_WBITS)
    else:
      data = r.payload.fields.get('load', '')

    if path == '/key/key.txt':
      key = data
    elif path.startswith('/chall/encrypt'):
      encrypted[path[-2:]] = data

open('encrypted.bin', 'wb').write(b64decode(''.join(x for _, x in sorted(encrypted.items()))))
