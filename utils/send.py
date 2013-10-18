#!/usr/bin/env python

import base64
import socket
import sys

if 2 != len(sys.argv):
    print "usage: sudo ./send.py (Base64 Encode String)"
    sys.exit(-1)
data = base64.b64decode(sys.argv[1])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(('eth0', 0))
s.send(data)
