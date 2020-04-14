# Print all pixels
# Example, output magenta pixels to find hex-encoded flag in the blue values:
# $ ./pixels.py google.png | grep -E '[0-9]+ 0 [0-9]+ [0-9]+'
# 255 0 112 255
# 255 0 121 255
# 255 0 110 255
# 255 0 53 255
# 255 0 116 255
# 255 0 50 255
# 255 0 49 255
# 255 0 104 255
# 255 0 111 255
# 255 0 48 255
# https://github.com/ctfs/write-ups-2015/tree/master/securinets-ctf-2015/stegano/google

from PIL import Image
import sys

im = Image.open(sys.argv[1])
bands = ''.join(im.getbands())
width, height = im.size
for h in range(height):
    for w in range(width):
	pixels = im.getpixel((w, h))
	if bands == 'RGBA':
	    r, g, b, a = pixels
	    print(r, g, b, a)
	elif bands == 'RGB':
	    r, g, b = pixels
	    print(r, g, b)
	else:
	    print(pixels)
    print()
