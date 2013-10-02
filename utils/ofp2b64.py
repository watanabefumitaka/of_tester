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

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser


def main():
    assert 2 == len(sys.argv)
    rfp = open(sys.argv[1], 'r')
    jsonstr = rfp.read()
    rfp.close()
    jsondict = json.loads(jsonstr)
    (key, value) = jsondict.popitem()
    cls = getattr(ofproto_v1_3_parser, key)
    msg = cls.from_jsondict(value, datapath=DummyDatapath())
    msg.version = ofproto_v1_3.OFP_VERSION
    msg.msg_type = msg.cls_msg_type
    msg.xid = 0
    msg.serialize()
    print base64.b64encode(msg.buf)

if __name__ == "__main__":
    main()
