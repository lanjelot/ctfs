#!/usr/bin/env python3
from dnslib.server import DNSServer, DNSLogger, DNSRecord, RR
import time
import sys
from itertools import cycle
#IPS = cycle('90.125.4.147', '169.254.169.254')
    
class TestResolver:

    def resolve(self,request,handler):
        q_name = str(request.q.get_qname())
        print('[<-] ' + q_name)

        reply = request.reply()
        ip = '90.125.4.147'
        print('[->] %s' % ip)

        reply.add_answer(*RR.fromZone(q_name + " 0 A %s" % ip))
        #reply.add_answer(*RR.fromZone(q_name + " 0 A 127.0.0.1"))
        return reply

logger = DNSLogger(prefix=False)
resolver = TestResolver()

server = DNSServer(resolver,port=53,address="127.0.0.1",logger=logger)
server.start_thread()

try:
    while True:
        time.sleep(1)
        sys.stderr.flush()
        sys.stdout.flush()

except KeyboardInterrupt:
    pass

finally:
    server.stop()
