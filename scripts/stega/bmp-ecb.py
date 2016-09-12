# nuit-du-hack-ctf-qualifications-2014 AnotherOne

# from https://gist.github.com/balidani/9999716
import Image
import sys
from sys import argv

def chunks(data, n):
    "Yield successive n-sized chunks from data"
    
    for i in xrange(0, len(data), n):
        yield data[i:i+n]

width = 1800
height = 4000 # some arbitrary height, but needs to be greater than width

def go(wh):
  width = int(wh.split('/')[0])
  height= int(wh.split('/')[1])

  img = Image.new('L', (width, height), 'white')
  img_data = list(img.getdata())

  bmp = open('crypted.bmp', 'rb').read()

  #white = bmp[0:16] # FAUX!
  white = bmp[0x40:0x50]

  reverse_chunks = list(chunks(bmp, 16))[::-1]
  for i, chunk in enumerate(reverse_chunks):
      for j in range(i * 6, (i +1) * 6):
          c = int(chunk == white) * 255
          img_data[j] = c

  img.putdata(img_data)
  img.transpose(Image.FLIP_LEFT_RIGHT)
  img.save('result.png')
  

#go(argv[1])
go(width, height)

# find the right bmp resolution
import Image
from sys import argv
import os

TEMP_FILE = '/tmp/img.bmp'
TARGET_FILE = '/home/seb/code/ctfs/ndhquals_2014-04-05/crypto300_AnotherOne/crypted.bmp'
TARGET_SIZE = os.stat(TARGET_FILE).st_size 

print('Target size: %d' % TARGET_SIZE)

#width = int(argv[1])
#height= int(argv[2])

def is_match(size, (i, j)):
  if size == TARGET_SIZE:
    print('Match width/height: %d/%d' % (i, j))
    return True
  else:
    return False

def test(i, j):
  img = Image.new('L', (i, j), 'white')
  img.save(TEMP_FILE)
  size = os.stat(TEMP_FILE).st_size 
  return size

def is_approx(size, (i, j)):
  coef = 10000
  if size/coef == TARGET_SIZE/coef:
    print('Approx match with %d (target: %d), width/height: %d/%d' % (size, TARGET_SIZE, i, j))

def bf(i_start, j_start):

  for i in xrange(i_start, 1800, 16):
    print('i: %d' % i)
    for j in xrange(j_start, 3000, 16):
  
      size = test(i, j)
      is_approx(size, (i, j))
      if size > TARGET_SIZE:
        break

i = int(argv[1])
j = int(argv[2])
size = test(i, j)
print('Size: %d' % size)
is_match(size, (i, j))

bf(i, j)
