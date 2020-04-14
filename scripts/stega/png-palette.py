# https://cesena.ing2.unibo.it/2014/04/14/plaidctf-2014-doge_stege-forensic-100/
# The first part of this script prints out the number of unique colors found in the palette, then duplicates are set to red.

import png
import collections
 
rd=png.Reader(filename='doge_stege.png')
rd.preamble()
pal=rd.palette()
 
histo=collections.Counter(pal)
print("Distinct colours ",len(list(histo.keys()))," of ",len(pal)," total")
 
img=rd.read_flat() # (w,h, not_resolved_pixel_array, metadata)
newpal=list()
for p in pal:          
  if p not in newpal:
     newpal.append(p)
  else:
     newpal.append( (255,0,0) )
 
pixels=img[2]
 
ofile=open('out.png','wb')
wr=png.Writer(width=img[0],height=img[1],greyscale=False,alpha=False,palette=newpal,planes=1)
wr.write_array(ofile,pixels)
ofile.close()
