# pragyan-ctf-2016 who made me
# recontructing png from a pickle file

def with_pil(maxx, maxy, blacks):
  from PIL import Image
  pixels = ''
  for x in range(maxx + 1):
    for y in range(maxy + 1):
      if (x, y) in blacks:
        pixels += chr(0) + chr(0) + chr(0)
      else:
        pixels += chr(245) + chr(245) + chr(245)
  
  im = Image.fromstring('RGB', (maxx, maxy), pixels)
  im.save('/tmp/done.png')

def with_scipy(maxx, maxy, blacks):
  import numpy as np
  import scipy.misc as smp
  pixels = np.zeros( (maxx, maxy, 3), dtype=np.uint8 )

  for x, y in blacks:
    pixels[x, y] = [245, 245, 245]

  #img = smp.toimage(pixels)
  smp.imsave('/tmp/done.png', pixels)

import pickle
blacks = pickle.load(open('pixels.jpg.pkl'))[1:]
print('number of black pixels: %d' % len(blacks))

maxx = max(x for x, y in blacks)
maxy = max(y for x, y in blacks)

print('maxx: %d, maxy: %d' % (maxx, maxy))

#maxx, maxy = 640, 800
with_scipy(maxx + 1, maxy + 1, blacks)
#with_pil(maxx, maxy, blacks)
