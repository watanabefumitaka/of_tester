import copy
import codecs
import inspect
import json
import os
import sys

#from ryu.lib import packet

# import all packet libraries.
PKT_LIB_PATH = 'ryu.lib.packet'
for modname, mod in sys.modules.iteritems():
    if not modname.startswith(PKT_LIB_PATH) or not mod:
        continue
    for (clsname, cls, ) in inspect.getmembers(mod):
        if not inspect.isclass(cls):
            continue
        exec 'from %s import %s' % (modname, clsname)


IN_DIR = '../tests/'
OUT_DIR = '../new_tests/'


# Ingress packets.
ETHER = ["ethernet(dst='22:22:22:22:22:22', src='11:11:11:11:11:11', ethertype=%s)",
         "ethernet(dst='bb:bb:bb:bb:bb:bb', src='aa:aa:aa:aa:aa:aa', ethertype=%s)"]
VLAN = ["vlan(pcp=3, cfi=0, vid=100, ethertype=%s)",
        "vlan(pcp=5, cfi=0, vid=203, ethertype=%s)",
        '33024']
MPLS = ["mpls(label=100, exp=3)",
        "mpls(label=203, exp=5)",
        '34887']
SVLAN = ["svlan(ethertype=%s, vid=10)",
         "svlan(ethertype=%s, vid=10)",
         '34984']
ITAG = ["itag(sid=100)",
        "itag(sid=203)",
        '35047']
IPV4 = ["ipv4(tos=32, proto=%s, src='192.168.10.10', dst='192.168.20.20')",
        "ipv4(tos=65, proto=%s, src='10.10.10.10', dst='10.10.20.20')",
        '2048']
IPV6 = ["ipv6(dst='20::20', flow_label=100, src='10::10')",
        "ipv6(dst='b0::b0', flow_label=203, src='a0::a0')",
        '34525']
IPV6_EXT = ["ipv6(dst='20::20',ext_hdrs=[hop_opts(data=[option(data='\\x00\\x00',len_=2,type_=5), option(data=None,len_=0,type_=1)],nxt=51,size=0), auth(data='\\xa0\\xe7\\xf8\\xab\\xf9i\\x1a\\x8b\\xf3\\x9f|\\xae',nxt=58,seq=1,size=4,spi=256)],flow_label=100, src='10::10')",
            "ipv6(dst='b0::b0', flow_label=203, src='a0::a0')",
            '34525']
TCP = ["tcp(dst_port=2222, option='\\x00\\x00\\x00\\x00', src_port=11111)",
       "tcp(dst_port=6789, option='\\x11\\x11\\x11\\x11', src_port=12345)",
       '6']
UDP = ["udp(dst_port=2222, src_port=11111)",
       "udp(dst_port=6789, src_port=12345)",
       '17']
ARP = ["arp(dst_ip='192.168.20.20',dst_mac='22:22:22:22:22:22', opcode=1, src_ip='192.168.10.10',src_mac='11:11:11:11:11:11')",
       "arp(dst_ip='10.10.20.20',dst_mac='bb:bb:bb:bb:bb:bb', opcode=2, src_ip='10.10.10.10',src_mac='aa:aa:aa:aa:aa:aa')",
       '2054']
SCTP = ["sctp(chunks=[chunk_data(payload_data='0123456789abcdefghijklmnopqrstuvwxyz')], dst_port=2222, src_port=11111)",
        "sctp(chunks=[chunk_data(payload_data='abcdefghijklmnopqrstuvwxyz0123456789')], dst_port=6789, src_port=12345)",
        '132']
ICMP = ["icmp(code=0,csum=0,data=echo(data='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL',id_=1,seq=1),type_=8)",
        "icmp(code=1,csum=0,data=dest_unreach(data='\\xd3]\\xb7\\xe3\\x9e\\xbb\\xf3\\xd6\\x9bq\\xd7\\x9f\\x82\\x18\\xa3\\x92Y\\xa7\\xa2\\x9a\\xab\\xb2\\xdb\\xaf\\xc3\\x1c\\xb3\\x00\\x10\\x83\\x10Q\\x87 \\x92\\x8b',data_len=1,mtu=1),type_=3)",
        '1']
ICMPV6 = ["icmpv6(code=0,csum=0,data=echo(data='\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !\"#$%&\\'()*+,-./0123',id_=30240,seq=0),type_=128)",
          "icmpv6(code=1,csum=0,data=nd_neighbor(data=nd_option_la(data=None,hw_src='aa:aa:aa:aa:aa:aa'),dst='a0::a0',length=1,res=0,type_=1),type_=135)",
         '58']
ICMPV6_NDSLL = ["icmpv6(code=1,csum=0,data=nd_neighbor(data=nd_option_la(data=None,hw_src='11:11:11:11:11:11'),dst='20::20',length=1,res=0,type_=1),type_=135)",
                "icmpv6(code=1,csum=0,data=nd_neighbor(data=nd_option_la(data=None,hw_src='aa:aa:aa:aa:aa:aa'),dst='b0::b0',length=1,res=0,type_=1),type_=135)",
                '58']
ICMPV6_NDTLL = ["icmpv6(code=1,csum=0,data=nd_neighbor(data=nd_option_la(data=None,hw_src='11:11:11:11:11:11'),dst='20::20',length=1,res=0,type_=1),type_=136)",
                "icmpv6(code=1,csum=0,data=nd_neighbor(data=nd_option_la(data=None,hw_src='aa:aa:aa:aa:aa:aa'),dst='b0::b0',length=1,res=0,type_=1),type_=136)",
                '58']
DATA = ["'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f '",
        "'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f '"]

L2_STACK = {'ether': [ETHER],
            'vlan': [ETHER, VLAN],
            'mpls': [ETHER, MPLS],
            'pbb': [ETHER, SVLAN, ITAG, ETHER, SVLAN, VLAN]}

L3_STACK_1 = {'ipv4_tcp': [IPV4, TCP],
              'ipv6_tcp': [IPV6, TCP],
              'arp': [ARP]}

L3_STACK_2 = {'ipv4_udp': [IPV4, UDP, DATA],
              'ipv4_sctp': [IPV4, SCTP],
              'ipv4_icmp': [IPV4, ICMP],
              'ipv6_udp': [IPV6, UDP],
              'ipv6_sctp': [IPV6, SCTP],
              'ipv6_icmp': [IPV6, ICMPV6],
              'ipv6_ndsll': [IPV6, ICMPV6_NDSLL],
              'ipv6_ndtll': [IPV6, ICMPV6_NDTLL],
              'ipv6_ext': [IPV6_EXT, TCP]}

# Default json data.
JSON_DATA = {"FLOW_MOD": [
                {"OFPFlowMod": {"command": 0,
                                "instructions": [
                                    {"OFPInstructionActions": {
                                        "actions": [{"OFPActionOutput": {"max_len": 65535, "port": 2}}],
                                        "type": 4}
                                    }
                                ],
                                "match": {
                                    "OFPMatch": {
                                        "oxm_fields": [
                                            {"OXMTlv": {"field": "eth_dst", "value": "aa:aa:aa:aa:aa:aa" }}
                                        ]
                                    }
                                },
                                "table_id": 0}
                }
             ],
             "description": "xxxxx",
             "packets": []
            }


# Test files.
MATCH_PATH = 'match/'
ACTIONS_PATH = 'actions/'
SET_FIELD_PATH = 'actions/25_SET_FIELD/'

#MATCH_SET_FIELD_TESTS = {'ether': ['03_ETH_DST']}

MATCH_SET_FIELD_TESTS = {'ether': ['00_IN_PORT',
                                   '01_IN_PHY_PORT',
                                   '02_METADATA', '02_METADATA_Mask',
                                   '38_TUNNEL_ID', '38_TUNNEL_ID_Mask',
                                   '03_ETH_DST', '03_ETH_DST_Mask',
                                   '04_ETH_SRC', '04_ETH_SRC_Mask',
                                   '05_ETH_TYPE'],
                         'vlan': ['06_VLAN_VID', '06_VLAN_VID_Mask',
                                  '07_VLAN_PCP'],
                         'mpls': ['34_MPLS_LABEL',
                                  '35_MPLS_TC',
                                  '36_MPLS_BOS'],
                         'pbb': ['37_PBB_ISID', '37_PBB_ISID_Mask'],
                         'ipv4_tcp': ['08_IP_DSCP_IPv4',
                                      '09_IP_ECN_IPv4',
                                      '10_IP_PROTO_IPv4',
                                      '11_IPV4_SRC', '11_IPV4_SRC_Mask',
                                      '12_IPV4_DST', '12_IPV4_DST_Mask',
                                      '13_TCP_SRC_IPv4',
                                      '14_TCP_DST_IPv4'],
                         'ipv4_udp': ['15_UDP_SRC_IPv4',
                                      '16_UDP_DST_IPv4'],
                         'ipv4_sctp': ['17_SCTP_SRC_IPv4',
                                       '18_SCTP_DST_IPv4'],
                         'ipv4_icmp': ['19_ICMPV4_TYPE',
                                       '20_ICMPV4_CODE'],
                         'ipv6_tcp': ['08_IP_DSCP_IPv6',
                                      '09_IP_ECN_IPv6',
                                      '10_IP_PROTO_IPv6',
                                      '13_TCP_SRC_IPv6',
                                      '14_TCP_DST_IPv6',
                                      '26_IPV6_SRC', '26_IPV6_SRC_Mask',
                                      '27_IPV6_DST', '27_IPV6_DST_Mask',
                                      '28_IPV6_FLABEL'],
                         'ipv6_ext': ['39_IPV6_EXTHDR', '39_IPV6_EXTHDR_Mask'],
                         'ipv6_udp': ['15_UDP_SRC_IPv6',
                                      '16_UDP_DST_IPv6'],
                         'ipv6_sctp': ['17_SCTP_SRC_IPv6',
                                       '18_SCTP_DST_IPv6'],
                         'ipv6_icmp': ['29_ICMPV6_TYPE',
                                       '30_ICMPV6_CODE'],
                         'ipv6_ndsll': ['31_IPV6_ND_TARGET',
                                        '32_IPV6_ND_SLL'],
                         'ipv6_ndtll': ['33_IPV6_ND_TLL'],
                         'arp': ['21_ARP_OP',
                                 '22_ARP_SPA', '22_ARP_SPA_Mask',
                                 '23_ARP_TPA', '23_ARP_TPA_Mask',
                                 '24_ARP_SHA', '24_ARP_SHA_Mask',
                                 '25_ARP_THA', '25_ARP_THA_Mask']}

ACTIONS_TESTS = {'ether': ['17_PUSH_VLAN',
                           '19_PUSH_MPLS',
                           '26_PUSH_PBB'],
                 'vlan': ['17_PUSH_VLAN_multiple',
                          '18_POP_VLAN'],
                 'mpls': ['11_COPY_TTL_OUT',
                          '12_COPY_TTL_IN',
                          '15_SET_MPLS_TTL',
                          '16_DEC_MPLS_TTL',
                          '19_PUSH_MPLS_multiple',
                          '20_POP_MPLS'],
                 'pbb': ['26_PUSH_PBB_multiple',
                         '27_POP_PBB'],
                 'ipv4_tcp': ['23_SET_NW_TTL_IPv4',
                              '24_DEC_NW_TTL_IPv4'],
                 'ipv6_tcp': ['23_SET_NW_TTL_IPv6',
                              '24_DEC_NW_TTL_IPv6']}


def convert_files(test_type, tests):
    for proto_type, tests in tests.items():
        for test in tests:
            in_path = '%s%s%s.json' % (IN_DIR, test_type, test)
            if os.path.isfile(in_path):
                json_buf = convert_file(proto_type, test_type, in_path)
            else:
                json_buf = convert_file(proto_type, test_type)

            out_path = OUT_DIR + in_path[len(IN_DIR):]
            with codecs.open(out_path, 'w', "utf-8") as f:
                json.dump(json_buf, f, sort_keys=True, indent=4, ensure_ascii=False)


def convert_file(proto_type, test_type, in_path=None):
    json_buf = (json.loads(open(in_path, 'rb').read())
                if in_path else [])
    num = 0
    if proto_type in L2_STACK:
        if MATCH_PATH == test_type and len(json_buf) > 9:
            json_buf = json_buf[:8]
        elif len(json_buf) > 3:
            json_buf = json_buf[:2]
            
        l2 = L2_STACK[proto_type]
        for l3 in L3_STACK_1.values():
            protocols = copy.copy(l2)
            protocols.extend(copy.copy(l3))
            json_buf, num = set_patckets(test_type, json_buf, num, protocols)
    else:
        if MATCH_PATH == test_type and len(json_buf) > 12:
            json_buf = json_buf[:11]
        elif len(json_buf) > 4:
            json_buf = json_buf[:3]

        l3 = (L3_STACK_1[proto_type] if proto_type in L3_STACK_1
              else L3_STACK_2[proto_type])
        for l2 in L2_STACK.values():
            protocols = copy.copy(l2)
            protocols.extend(copy.copy(l3))
            json_buf, num = set_patckets(test_type, json_buf, num, protocols)

    return json_buf


def set_patckets(test_type, json_buf, num, protocols):
    ok_pkt = []
    ng_pkt = []

    for i, protocol in enumerate(protocols):
        for j in range(0, 2):
            if '%s' in protocol[j]:
                protocol[j] %= protocols[i+1][2]
        ok_pkt.append(protocol[0])
        ng_pkt.append(protocol[1])

    # for "egress".
    if len(json_buf)-1 < num:
        json_buf.append(copy.copy(JSON_DATA))
    json_buf[num]['packets'] = [{'ingress': ok_pkt,
                                 'egress': ok_pkt}]
    json_buf[num]['FLOW_MOD'] = json_buf[0]['FLOW_MOD']
    num += 1

    if MATCH_PATH == test_type:
        # for "PACKET_IN".
        if len(json_buf)-1 < num:
            json_buf.append(copy.copy(JSON_DATA))
        json_buf[num]['packets'] = [{'ingress': ok_pkt,
                                     'PACKET_IN': ok_pkt}]
        json_buf[num]['FLOW_MOD'] = json_buf[0]['FLOW_MOD']
        json_buf[num]['FLOW_MOD'][0]['OFPFlowMod']['instructions'][0]['OFPInstructionActions']['actions'][0]['OFPActionOutput']['port'] = 4294967293
        num += 1
        # for "table-miss".
        if len(json_buf)-1 < num:
            json_buf.append(copy.copy(JSON_DATA))
        json_buf[num]['packets'] = [{'ingress': ng_pkt}]
        json_buf[num]['FLOW_MOD'] = json_buf[0]['FLOW_MOD']
        num += 1

    return json_buf, num


test_dir = OUT_DIR
if not os.path.isdir(test_dir):
    os.system('mkdir %s' % test_dir)

test_dir = OUT_DIR + MATCH_PATH
if not os.path.isdir(test_dir):
    os.system('mkdir %s' % test_dir)

test_dir = OUT_DIR + ACTIONS_PATH
if not os.path.isdir(test_dir):
    os.system('mkdir %s' % test_dir)

test_dir = OUT_DIR + SET_FIELD_PATH
if not os.path.isdir(test_dir):
    os.system('mkdir %s' % test_dir)

convert_files(MATCH_PATH, MATCH_SET_FIELD_TESTS)
convert_files(ACTIONS_PATH, ACTIONS_TESTS)
convert_files(SET_FIELD_PATH, MATCH_SET_FIELD_TESTS)
