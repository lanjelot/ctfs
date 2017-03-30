# plaidctf-2015 curious
# https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/crypto/curious
# another implementation: https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/PCTF/crypto/curious

############################
## Wiener's Attack module ##
############################

# Calculates bitlength
def bitlength(x):
  assert x >= 0
  n = 0
  while x > 0:
    n = n+1
    x = x>>1
  return n
  
# Squareroots an integer
def isqrt(n):
  if n < 0:
    raise ValueError('square root not defined for negative numbers')  
  if n == 0:
    return 0
  a, b = divmod(bitlength(n), 2)
  x = 2**(a+b)
  while True:
    y = (x + n//x)//2
    if y >= x:
      return x
    x = y

# Checks if an integer has a perfect square
def is_perfect_square(n):
  h = n & 0xF; #last hexadecimal "digit"    
  if h > 9:
    return -1 # return immediately in 6 cases out of 16.
  # Take advantage of Boolean short-circuit evaluation
  if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
    # take square root if you must
    t = isqrt(n)
    if t*t == n:
      return t
    else:
      return -1    
  return -1

# Calculate a sequence of continued fractions
def partial_quotiens(x, y):
  partials = []
  while x != 1:
    partials.append(x // y)
    a = y
    b = x % y
    x = a
    y = b
  #print partials
  return partials

# Helper function for convergents
def indexed_convergent(sequence):
  i = len(sequence) - 1
  num = sequence[i]
  denom = 1
  while i > 0:
    i -= 1
    a = (sequence[i] * num) + denom
    b = num
    num = a
    denom = b
  #print (num, denom)
  return (num, denom)

# Calculate convergents of a  sequence of continued fractions
def convergents(sequence):
  c = []
  for i in range(1, len(sequence)):
    c.append(indexed_convergent(sequence[0:i]))
  #print c
  return c

# Calculate `phi(N)` from `e`, `d` and `k`
def phiN(e, d, k):
  return ((e * d) - 1) / k

# Wiener's attack, see http://en.wikipedia.org/wiki/Wiener%27s_attack for more information
def wiener_attack(N,e):
  (p,q,d) = (0,0,0)
  conv=convergents(partial_quotiens(e,N))
  for frac in conv:
    (k,d)=frac
    if k == 0:
      continue
    y = -(N - phiN(e, d, k) + 1)
    discr = y*y - 4*N
    if(discr>=0):
      # since we need an integer for our roots we need a perfect squared discriminant
      sqr_discr = is_perfect_square(discr)
      # test if discr is positive and the roots are integers
      if sqr_discr!=-1 and (-y+sqr_discr)%2==0:
        p = ((-y+sqr_discr)/2)
        q = ((-y-sqr_discr)/2)
        return p, q, d
  return p, q, d

if __name__ == '__main__':
  N = 0x9C2F6505899120906E5AFBD755C92FEC429FBA194466F06AAE484FA33CABA720205E94CE9BF5AA527224916D1852AE07915FBC6A3A52045857E0A1224C72A360C01C0CEF388F1693A746D5AFBF318C0ABF027661ACAB54E0290DFA21C3616A498210E2578121D7C23877429331D428D756B957EB41ECAB1EAAD87018C6EA3445
  e = 0x466A169E8C14AC89F39B5B0357EFFC3E2139F9B19E28C1E299F18B54952A07A932BA5CA9F4B93B3EAA5A12C4856981EE1A31A5B47A0068FF081FA3C8C2C546FEAA3619FD6EC7DD71C9A2E75F1301EC935F7A5B744A73DF34D21C47592E149074A3CCEF749ECE475E3B6B0C8EECAC7C55290FF148E9A29DB8480CFE2A57801275
  c = 0x6ce2062b5986956358cbecf09e1de2fea13600532f42be838ab102014c5fd4d0c62a472c918e29c788cc27b9abc4c28894c625e3cbed8de80d31c8d483992fe9c2aba39e49fe9f1b58de1bd5c79d9588b050974261fec74fb4fa1a9050d285c200fd988aeb507b1128c8520806210cafa73f8c33e62614ff767478e4829d1017

  p, q, d = wiener_attack(N, e)

  print 'found d: 0x%x' % d

  m = pow(c, d, N)
  print 'msg: %d %r' % (m, ('%x' % m).decode('hex'))

# vim: ts=2 sw=2 sts=2 et fdm=marker bg=dark
