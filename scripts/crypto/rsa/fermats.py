def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

def fermat(n, verbose=False):
  a = isqrt(n) # int(ceil(n**0.5))
  b2 = a*a - n
  b = isqrt(n) # int(b2**0.5)
  count = 0
  while b*b != b2:
   if verbose:
     print('Trying: a=%s b2=%s b=%s' % (a, b2, b))
   a = a + 1
   b2 = a*a - n
   b = isqrt(b2) # int(b2**0.5)
   count += 1
  p=a+b
  q=a-b
  assert n == p * q
  print('a=',a)
  print('b=',b)
  print('p=',p)
  print('q=',q)
  print('pq=',p*q)
  return p, q

if __name__ == '__main__':
  n = 103591*104729
  n = 163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013L

  import sys
  n = int(sys.argv[1], 16)
  print('n=', n)
  fermat(n)
