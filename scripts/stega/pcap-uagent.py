# su-ctf-2016 uagent

from scapy.all import *
from scapy.layers import http
import base64

pcap = rdpcap('ragent.pcap')
req = [p for p in pcap if p.haslayer(http.HTTPRequest)]

with open('flag.png', 'wb') as png:
  saved = []
  for p in req:
    if p['TCP'].seq in saved:
        continue
    #print 'seq: %r' % p['TCP'].seq
    saved.append(p['TCP'].seq)

    r = p.getlayer(http.HTTPRequest)
    png.write(base64.b64decode(r.fields['User-Agent'][9:-1]))

# lucky the fragments of the png are not out of order like the zip

req = [p for p in pcap if p.haslayer(http.HTTPResponse)]

with open('flag.zip', 'wb') as f:
  for p in req:
    r = p.getlayer(http.HTTPResponse)

    idx = r.fields['Content-Range'].index('-')
    start = int(r.fields['Content-Range'][6:idx])

    f.seek(start)
    f.write(r.payload.load)
