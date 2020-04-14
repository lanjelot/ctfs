from scapy.all import *
from time import localtime, strftime
import argparse

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

def esc(m):
    return r'\x%02x' % ord(m.group(1))

def filter_http(p):
    if not p.haslayer(TCP):
        return False
    if not p.haslayer(Raw):
        return False

    if args.ports:
        if not (p[TCP].dport in args.ports or p[TCP].sport in args.ports):
            return False

    if args.dst:
        return p[IP].dst == args.dst
    else:
        return True

def print_http(p):

    strtime = strftime('%Y-%m-%d %H:%M:%S', localtime(p.time))
    #pp = raw(p[Raw])
    pp = re.sub(r'([^\x0d\x0a\x20-\x7F])', esc, raw(p[Raw]).decode('latin1'))

    print('-- %s - %s:%d -> %s:%d' % (strtime, p[IP].src, p[IP].sport, p[IP].dst, p[IP].dport))
    print('%s' % pp)
    #print('%s - [%s]\n%s' % (p[IP].src, strtime, pp))

if __name__ == '__main__':
    ONLY_PORTS = '80,8080,8082,8181,8008,1234'

    from sys import argv
    parser = argparse.ArgumentParser(prog=argv[0])
    parser.add_argument('-i', dest='iface', default='eth0', help='interface to sniff')
    parser.add_argument('-r', dest='pcap', default='', help='pcap to parse')
    parser.add_argument('-d', dest='dst', default='', help='destination IP address')
    parser.add_argument('-f', dest='capture_filter', default='tcp', help='capture filter')
    parser.add_argument('-p', '--ports', dest='ports', default=ONLY_PORTS, help='ignore packets with dport or sport not in this whitelist')
  
    args = parser.parse_args(argv[1:])
    args.ports = [int(p) for p in args.ports.split(',')]

    npacket = 0
    if args.pcap:
        pcap = rdpcap(args.pcap)
        for p in pcap:
            npacket += 1
            if filter_http(p):
                print_http(p)
        print('Read %d packets' % npacket)
    else:
        print('Sniffing: %s\nFilter: %s\n' % (args.iface, args.capture_filter))
        sniff(iface=args.iface, filter=args.capture_filter, store=False, promisc=False, lfilter=filter_http, prn=print_http)
