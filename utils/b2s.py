#!/usr/bin/env python

import base64
import sys

from ryu.lib.packet import packet

if 2 != len(sys.argv):
  print 'b2s.py [base64encode string]  -> stringify text'
  sys.exit(-1)
data = base64.b64decode(sys.argv[1])
pkt = packet.Packet(data)
print pkt
