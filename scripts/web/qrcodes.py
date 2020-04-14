import requests
import subprocess

filename = 'entrance.svg'

while True:
  r = requests.get('http://web.lasactf.com:63017/' + filename)
  tmp_filename = "/tmp/%s" %(filename)
  f = open(tmp_filename, 'w')
  f.write(r.text)
  f.close()

  p = subprocess.Popen(['zbarimg', tmp_filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out, err = p.communicate()
  print(out)
  filename = out.split("\n")[0].rstrip().split('/')[-1]
  if "lasactf{" in out:
    break
