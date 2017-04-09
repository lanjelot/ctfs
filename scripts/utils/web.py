#!/usr/bin/env python

import sys
import BaseHTTPServer, SimpleHTTPServer
import ssl
import cgi
import os

import logging
fmt = logging.Formatter('-- %(source_ip)s [%(asctime)s]\n%(message)s')
fh = logging.FileHandler('/tmp/webpy.log')
fh.setFormatter(fmt)
fh.setLevel(logging.DEBUG)

logger = logging.getLogger('webpy')
logger.setLevel(logging.DEBUG)
logger.addHandler(fh)

class MyHTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def parse_request(self):

        r = SimpleHTTPServer.SimpleHTTPRequestHandler.parse_request(self)

        trace = '%s\n%s' % (self.raw_requestline.rstrip('\r\n'), self.headers)

        if self.command == 'POST':
            clen = int(self.headers['Content-Length'])
            body = self.rfile.read(clen)
            trace += '\n' + body

        logger.info(trace, extra={'source_ip': self.client_address[0]})
        return r

    def log_message(self, format, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format%args))

        #if '?' in self.path:
        #    query = self.path.split('?', 1)[1]
        #    sys.stderr.write("%s" % query.decode('base64'))

    def send_head(self):

        path = self.translate_path(self.path)

        if path.endswith('wh'):
            self.send_response(302)
            self.send_header('Location', '/index.html')
            self.end_headers()
            return

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
            self.send_header('Access-Control-Allow-Origin', '*')
            #self.send_header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-Secret')
            #self.send_header('Access-Control-Allow-Headers', 'Content-Type, *')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT')
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()
            return f
        except:
            f.close()
            raise

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
        if '43' in sys.argv[1]:
            https = True
            port = int(sys.argv[1])
        else:
            port = int(sys.argv[1])

    if https:
        print 'HTTPs on *:%d' % port
        httpd = BaseHTTPServer.HTTPServer(('', port), MyHTTPHandler)
        httpd.socket = ssl.wrap_socket (httpd.socket, certfile='/home/seb/code/ssl-certs/certkey.pem', server_side=True)
        httpd.serve_forever()

    else:
        BaseHTTPServer.test(MyHTTPHandler, BaseHTTPServer.HTTPServer)

