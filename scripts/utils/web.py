#!/usr/bin/env python3

import sys
from http.server import SimpleHTTPRequestHandler, HTTPServer
import ssl
import os
from time import sleep
from base64 import b64decode
from pathlib import Path
import logging
from urllib.parse import parse_qs

class MyHTTPHandler(SimpleHTTPRequestHandler):

    def parse_request(self):

        r = SimpleHTTPRequestHandler.parse_request(self)
        trace = '%s\n%s' % (self.raw_requestline.decode('utf-8').rstrip('\r\n'), self.headers)

        if self.command == 'POST':
            clen = int(self.headers['Content-Length'])
            body = self.rfile.read(clen)
            #trace += '\n' + b64decode(body).decode('utf-8')
            trace += '\n' + body.decode('utf-8')

        if self.path == '/favicon.ico':
            return r

        logger.info(trace, extra={'source_ip': self.client_address[0]})
        return r

    def log_message(self, fmtstr, *args):

        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0],
          self.log_date_time_string(), fmtstr % args))

        # if '?' in self.path:
        #     import zlib
        #     query = self.path.split('?', 1)[1]
            #sys.stderr.write("%s" % zlib.decompress(query.decode('base64'), -zlib.MAX_WBITS))
            #sys.stderr.write("%s" % query.decode('base64'))

    def send_head(self):
        # rdp gateway
        #self.protocol_version = 'HTTP/1.1'
        #self.server_version = 'Microsoft-HTTPAPI/2.0'
        #if self.headers['Authorization'] == 'Basic ZGVtbzpkZW1vbw==':
        #    self.send_response(200)
        #    self.end_headers()
        #    sleep(10)
        #else:
        #    self.send_response(401)
        #    self.end_headers()
        #return

        if self.path.endswith('/re'):
            self.send_response(302)
            with open('/tmp/urls.txt') as f:
                target = f.readline().strip()
            logger.info(f'Location: {target}', extra={'source_ip': self.client_address[0]})
            self.send_header('Location', target)
            self.end_headers()
            return

        if '?' in self.path:
            qs = parse_qs(self.path.split('?', 1)[1])

            if 'r' in qs:
                target = qs['r'][0]
                logger.info(f'Location: {target}', extra={'source_ip': self.client_address[0]})

                self.send_response(302)
                self.send_header('Location', target)
                self.end_headers()
                return

        path = self.translate_path(self.path)

        if os.path.isdir(path):
            path = 'index.html'

        if path.endswith('secret'):
            ctype = 'application/text'
        else:
            ctype = self.guess_type(path)

        f = None

        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        try:
            self.send_response(200)
            self.send_header("Content-type", ctype)
            fs = os.fstat(f.fileno())
            self.send_header("Content-Length", str(fs[6]))
            #self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            #self.send_header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-Secret')
            self.send_header('Access-Control-Allow-Origin', 'http://ix.ix.tc')
            self.send_header('Access-Control-Allow-Headers', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT')
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()
            return f
        except:
            f.close()
            raise

    def do_RDG_OUT_DATA(self):
        return self.do_GET()

    def do_POST(self):
        return self.do_GET()

    def do_OPTIONS(self):
        return self.do_GET()

    def log_error(self, format, *args):
        pass

if __name__ == '__main__':
    https = False
    port = 1234

    if len(sys.argv) == 2:
        port = int(sys.argv[1])
        if '43' in sys.argv[1]:
            https = True

    httpd = HTTPServer(('', port), MyHTTPHandler)

    if https:
        # b.e.uk.to expires 2021-03-24
        # *.d2t.b.e.uk.to expires 2021-05-08
        # renew with: certbot certonly --manual --config-dir ~/code/certs/letsencrypt/etc --work-dir ~/code/certs/letsencrypt/lib --logs-dir ~/code/certs/letsencrypt/log -d b.e.uk.to
        # install certbot with: pip install -U certbot --user
        httpd.socket = ssl.wrap_socket(httpd.socket,
         certfile='/home/vagrant/code/certs/letsencrypt/etc/live/b.e.uk.to-0001/fullchain.pem',
          keyfile='/home/vagrant/code/certs/letsencrypt/etc/live/b.e.uk.to-0001/privkey.pem',
         #certfile='/home/vagrant/code/certs/letsencrypt/etc/live/d2t.b.e.uk.to/fullchain.pem',
         # keyfile='/home/vagrant/code/certs/letsencrypt/etc/live/d2t.b.e.uk.to/privkey.pem',
           server_side=True)

    fmt = logging.Formatter('-- %(source_ip)s [%(asctime)s]\n%(message)s')
    fh = logging.FileHandler('/tmp/webpy-%d.log' % port)
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)

    logger = logging.getLogger('webpy')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    print('HTTP%s on *:%d' % ('s' if https else '', port))
    httpd.serve_forever()
