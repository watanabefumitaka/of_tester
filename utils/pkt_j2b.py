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
import inspect
import json
import sys

import ryu.lib.packet

_COMMON_PATH = 'ryu.lib.packet.'
_PROTOCOL_STACK = {}


def get_protocols():
    for modname, mod in sys.modules.iteritems():
        if not modname.startswith(_COMMON_PATH) or not mod:
            continue
        modname = modname.replace(_COMMON_PATH, '')
        for (clsname, cls, ) in inspect.getmembers(mod):
            if not inspect.isclass(cls):
                continue
            for basecls in inspect.getmro(cls):
                if 'PacketBase' != basecls.__name__:
                    continue
                _PROTOCOL_STACK[clsname] = cls


def main():
    assert 2 == len(sys.argv)
    rfp = open(sys.argv[1], 'r')
    jsonstr = rfp.read()
    rfp.close()
    jsonlist = json.loads(jsonstr)
    get_protocols()
    pkt = ryu.lib.packet.packet.Packet()
    for jsondict in jsonlist:
        for key, value in jsondict.iteritems():
            cls_ = _PROTOCOL_STACK.get(key)
            stack = cls_.from_jsondict(value) if cls_ \
                else base64.b64decode(value)
            pkt.add_protocol(stack)
    pkt.serialize()
    data = base64.b64encode(pkt.data)
    print data
    print pkt

if __name__ == "__main__":
    main()
