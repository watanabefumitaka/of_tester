#!/usr/bin/env python
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json
import sys

from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import mpls
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan

_PROTOCOL_STACK = {'arp': arp.arp,
                   'ethernet': ethernet.ethernet,
                   'icmp': icmp.icmp,
                   'icmpv6': icmpv6.icmpv6,
                   'ipv4': ipv4.ipv4,
                   'ipv6': ipv6.ipv6,
                   'mpls': mpls.mpls,
                   'tcp': tcp.tcp,
                   'udp': udp.udp,
                   'vlan': vlan.vlan}


def main():
    assert 2 == len(sys.argv)
    rfp = open(sys.argv[1], 'r')
    jsonstr = rfp.read()
    rfp.close()
    jsonlist = json.loads(jsonstr)
    pkt = packet.Packet()
    for jsondict in jsonlist:
        for key, value in jsondict.iteritems():
            cls_ = _PROTOCOL_STACK.get(key)
            stack = (cls_.from_jsondict(value) if cls_ else value)
            pkt.add_protocol(stack)
    pkt.serialize()
    print base64.b64encode(pkt.data)

if __name__ == "__main__":
    main()
