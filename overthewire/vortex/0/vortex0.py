#!/usr/bin/env python

import socket
import struct

s = socket.create_connection(('vortex.labs.overthewire.org', 5842))
s.sendall(struct.pack('<Q', sum(struct.unpack('<IIII', s.recv(4*4, socket.MSG_WAITALL)))))
print s.recv(1024)
