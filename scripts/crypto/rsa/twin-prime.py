def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

n = 0x86E996013E77C41699000E0941D480C046B2F71A4F95B350AC1A4D426372923D8A4561D96FBFB0240595907201AD3225CF6EDED7DE02D91C386FFAC280B72D0F95CAE71F42EBE0D3EDAEACE7CEA3195FA32C1C6080D90EF853D06DD4572C92B9F8310BBC0C635A5E26952511751030A6590816554E763031BCBB31E3F119C65F
import sys
n = int(sys.argv[1], 16)
e = 65537

i = isqrt(n)

p, q = 0, 0

while True:
  if n - (i * (n / i)) == 0:
    p = i
    q = n/i
    break
  i += 1

print 'p:', p
print 'q:', q
