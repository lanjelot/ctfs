from PIL import Image

img = Image.open('/home/seb/pragyan-ctf-2016/stega/landscape/landscape.png')
width, height = img.size

greys = ''
for x in range(0, width, 7):
  #for y in xrange(height):
  y = 50
  r, g, b = img.getpixel((x, y))
  if r == g and r == b:
    #print 'grey at: %d %d (%x)' % (x, y, r)
    greys += chr(r)

print('greys=', greys)
