# su-ctf-2016 blocks
# asis-quals-ctf-2016 odrrere

import struct
import sys

def crc32(data):
    #import binascii
    #return binascii.crc32(data)
    import zlib
    return zlib.crc32(data)

def read_chunk2(filename):
    import png
    f = png.Reader(filename)
    chunk = f.chunk(lenient=True)
   
    crc = (binascii.crc32(chunk[0] + chunk[1]) & 0xffffffff)
    raw = struct.pack(">L", len(chunk[1])) + chunk[0] + chunk[1] + struct.pack(">L", crc)
    return raw

def read_chunk(f):
    chk_len = f.read(4)
    if len(chk_len) == 0:
        return None
    size = struct.unpack('>I', chk_len)[0]
    chk_type = f.read(4)
    chk_data = f.read(size)
    chk_crc = f.read(4)
    assert struct.pack('>l', crc32(chk_type + chk_data)) == chk_crc
    return chk_type, chk_data, chk_len + chk_type + chk_data + chk_crc

with open('odrrere.png', 'rb') as f:
    header = f.read(8)
    idat = []
    end = None

    out = header
    while True:
        chunk = read_chunk(f)
        if chunk is None:
            break
        typ, data, raw = chunk
        print('got %s' % typ)
        if typ == 'IDAT':
            idat.append(raw)
        elif typ == 'IEND':
            end = raw
        else:
            out += raw

    order = [0, 12, 8, 4, 9, 10, 6, 7, 3, 5, 2, 11, 1] # map(int, sys.argv[1:])
    for i in order:
        out += idat[i]
    out += end
    open('/tmp/out.png', 'wb').write(out)
