import json
import os


IN_DIR = '../tests/'
OUT_DIR = '../new_tests/'


MATCH_LIST = {'in_port': [0, None],
              'in_phy_port': [1, None],
              'metadata': [2, None],
              'eth_dst': [3, 'ethernet'],
              'eth_src': [4, 'ethernet'],
              'eth_type': [5, 'ethernet'],
              'vlan_vid': [6, 'vlan'],
              'vlan_pcp': [7, 'vlan'],
              'ip_dscp': [8, ['ipv4', 'ipv6']],
              'ip_ecn': [9, ['ipv4', 'ipv6']],
              'ip_proto': [10, 'ipv4'],
              'ipv4_src': [11, 'ipv4'],
              'ipv4_dst': [12, 'ipv4'],
              'tcp_src': [13, 'tcp'],
              'tcp_dst': [14, 'tcp'],
              'udp_src': [15, 'udp'],
              'udp_dst': [16, 'udp'],
              'sctp_src': [17, 'sctp'],
              'sctp_dst': [18, 'sctp'],
              'icmpv4_type': [19, 'icmp'],
              'icmpv4_code': [20, 'icmp'],
              'arp_op': [21, 'arp'],
              'arp_spa': [22, 'arp'],
              'arp_tpa': [23, 'arp'],
              'arp_sha': [24, 'arp'],
              'arp_tha': [25, 'arp'],
              'ipv6_src': [26, 'ipv6'],
              'ipv6_dst': [27, 'ipv6'],
              'ipv6_flabel': [28, 'ipv6'],
              'icmpv6_type': [29, 'icmpv6'],
              'icmpv6_code': [30, 'icmpv6'],
              'ipv6_nd_target': [31, 'icmpv6'],
              'ipv6_nd_sll': [32, 'icmpv6'],
              'ipv6_nd_tll': [33, 'icmpv6'],
              'mpls_label': [34, 'mpls'],
              'mpls_tc': [35, 'mpls'],
              'mpls_bos': [36, 'mpls'],
              'pbb_isid': [37, 'itag'],
              'tunnel_id': [38, 'None'],
              'ipv6_exthdr': [39, 'ipv6']}


INSTRUCTION = {'OFPInstructionWriteMetadata': ['write_metadata:',
                                               ['metadata', 'metadata_mask']],
               'OFPInstructionGotoTable': ['goto_table:', ['table_id']],
               'OFPActionOutput': ['output:', ['port']],
               'OFPActionSetField': ['set_field:', ['value', 'field']],
               'OFPActionPushVlan': ['push_vlan:', ['ethertype']],
               'OFPActionPushMpls': ['push_mpls:', ['ethertype']],
               'OFPActionPushPbb': ['push_pbb:', ['ethertype']],
               'OFPActionPopVlan': ['pop_vlan'],
               'OFPActionPopMpls': ['pop_mpls'],
               'OFPActionPopPbb': ['pop_pbb'],
               'OFPActionSetNwTtl': ['set_nw_ttl:', ['nw_ttl']],
               'OFPActionDecNwTtl': ['dec_nw_ttl'],
               'OFPActionSetMplsTtl': ['set_mpls_ttl:', ['mpls_ttl']],
               'OFPActionDecMplsTtl': ['dec_mpls_ttl'],
               'OFPActionCopyTtlIn': ['copy_ttl_in'],
               'OFPActionCopyTtlOut': ['copy_ttl_out']}

CONV_KEY = {'eth_type': 'ethertype',
            'eth_src': 'src',
            'eth_dst': 'dst',
            'vlan_vid': 'vid',
            'vlan_pcp': 'pcp',
            'ip_proto': 'proto',
            'ipv4_src': 'src',
            'ipv4_dst': 'dst',
            'ip_dscp': ['tos', 'traffic_class'],
            'ip_ecn': ['tos', 'traffic_class'],
            'ipv6_src': 'src',
            'ipv6_dst': 'dst',
            'ipv6_flabel': 'flow_label',
            'ipv6_exthdr': 'ext_hdrs',
            'ipv6_nd_target': 'dst',
            'ipv6_nd_sll': 'src',
            'ipv6_nd_tll': 'hw_src',
            'tcp_src': 'src_port',
            'tcp_dst': 'dst_port',
            'udp_src': 'src_port',
            'udp_dst': 'dst_port',
            'sctp_src': 'src_port',
            'sctp_dst': 'dst_port',
            'arp_op': 'opcode',
            'arp_sha': 'src_mac',
            'arp_tha': 'dst_mac',
            'arp_spa': 'src_ip',
            'arp_tpa': 'dst_ip',
            'icmpv4_type': 'type_',
            'icmpv4_code': 'code',
            'icmpv6_type': 'type_',
            'icmpv6_code': 'code',
            'mpls_label': 'label',
            'mpls_bos': 'bsb',
            'pbb_isid': 'sid',
            'mpls_tc': 'exp'}

def convert_files(path):
    if os.path.isdir(path):  # Directory
        for test_path in os.listdir(path):
            test_path = path + (test_path if path[-1:] == '/'
                                else '/%s' % test_path)
            convert_files(test_path)

    elif os.path.isfile(path):  # File
        (dummy, ext) = os.path.splitext(path)
        if ext == '.json':
            buf = open(path, 'rb').read()
            json_buf = json.loads(buf)
            descriptions = make_description(json_buf)
            write_file(path, descriptions)


def make_description(json_buf):
    descriptions = {}

    for i, buf in enumerate(json_buf):
        if i == 0:
            continue

        flows = []
        match = {}

        # Flow description
        for flow in buf['prerequisite']:
            tbl_match = {}
            # analyze Match
            if 'match' in flow['OFPFlowMod']:
                for match_field in flow['OFPFlowMod']['match']['OFPMatch']['oxm_fields']:
                    if (('table_id' not in match or
                            flow['OFPFlowMod']['table_id'] > match['table_id']) or
                            MATCH_LIST[match_field['OXMTlv']['field']][0] > match['num']):
                        match['table_id'] = flow['OFPFlowMod']['table_id']
                        match['num'] = MATCH_LIST[match_field['OXMTlv']['field']][0]
                        match['proto'] = MATCH_LIST[match_field['OXMTlv']['field']][1]
                        match['key'] = match_field['OXMTlv']['field']
                    if (not 'num' in tbl_match or
                            MATCH_LIST[match_field['OXMTlv']['field']][0] > tbl_match['num']):
                        tbl_match['num'] = MATCH_LIST[match_field['OXMTlv']['field']][0]
                        str_tmp = '%s=0x%04x' if match_field['OXMTlv']['field'] == 'eth_type' else '%s=%s'
                        if match_field['OXMTlv']['field'] == 'vlan_vid':
                            match_field['OXMTlv']['value'] &= 0xfff 
                        tbl_match['value'] = str_tmp % (match_field['OXMTlv']['field'],
                                                        match_field['OXMTlv']['value'])
                        if 'mask' in match_field['OXMTlv'] and match_field['OXMTlv']['mask']:
                            tbl_match['value'] += ('(mask=0x%x)' % match_field['OXMTlv']['mask'])
            tbl_match_str = '%s' % tbl_match['value'] if tbl_match else ''

            # analyze Instructions
            instructions = []
            for inst in flow['OFPFlowMod']['instructions']:
                for key, value in inst.items():
                    if key == 'OFPInstructionActions':
                        for action in value['actions']:
                            instructions.append(get_inst_str(action))
                    else:
                        instructions.append(get_inst_str(inst))

            action_str = 'actions=%s' % ', '.join(instructions)

            # flow description
            flow_str = (action_str if tbl_match_str == ''
                        else '%s, %s' % (tbl_match_str, action_str))
            if flow['OFPFlowMod']['table_id'] != 0:
                flow_str = 'table_id=%s, %s' % (flow['OFPFlowMod']['table_id'],
                                                flow_str)
            flows.append('\'%s\'' % flow_str)
        flows_str = ', '.join(flows)

        # Packet description
        pkts = []
        for proto in buf['tests'][0]['ingress']:
            p = ('str' if '\\' in proto 
                    and (not 'tcp' in proto and not 'udp' in proto
                          and not 'icmp' in proto)
                else proto.split('(', 1)[0])
            if 'proto' in match:
                match_proto = ([match['proto']]
                               if type(match['proto']) != list
                               else match['proto'])
                for match_p in match_proto:
                    if p == match_p:
                        data = get_pkt_data(proto, match['key'])
                        p = '%s%s' % (p, data)
                        break
            pkts.append(p)
        pkt_str = '/'.join(pkts)

        descriptions[i-1] = '%s-->%s' % (pkt_str, flows_str)

    return descriptions


def get_inst_str(inst):
    key = inst.keys()[0]
    inst_str = INSTRUCTION[key][0]
    if len(INSTRUCTION[key]) == 2:
        for i, value in enumerate(INSTRUCTION[key][1]):
            if i != 0:
                inst_str += '/'

            if value == 'ethertype':
                str_tmp = '0x%04x'
            elif 'mask' in value:
                str_tmp = '0x%x'
            else:
                str_tmp = '%s'
            data = (inst[key] if key != 'OFPActionSetField'
                    else inst[key]['field']['OXMTlv'])
            if value == 'port' and data[value] == 4294967293:
                inst_str += 'CONTROLLER'            
            else:
                inst_str += (str_tmp % data[value])
                
    return inst_str

def get_pkt_data(proto, proto_key):
    keys = (proto_key if proto_key not in CONV_KEY
           else CONV_KEY[proto_key])
    if type(keys) != list:
        keys = [keys]

    for key in keys:
        if key in proto:
            pkt_data = proto.split(key+'=', 1)[1]
            if proto_key != 'ipv6_exthdr':
                pkt_data = pkt_data.split(',', 1)[0]
                if pkt_data[-1] == ')':
                    pkt_data = pkt_data[:-1]
                if proto_key == 'eth_type':
                    pkt_data = '0x%04x' % int(pkt_data)
                return '(%s=%s)' % (key, pkt_data)
            else:
                pkt_data = pkt_data.split('],', 1)[0]
                if pkt_data[-1] == ')':
                    pkt_data = pkt_data[:-1]
                return '(%s=%s)]' % (key, pkt_data)

    return ''


def write_file(path, descriptions):
    buf = open(path, 'rb').readlines()

    write_buf = []
    cnt = 0
    for text in buf:
        if 'description' in text:
            write_text = ('        \"description\":\"%s\",\n'
                          % descriptions[cnt])
            write_buf.append(write_text)
            cnt += 1
        else:
            write_buf.append(text)

    path = OUT_DIR + path[len(IN_DIR):]
    f = open(path, "w")
    f.writelines(write_buf)
    f.close()


# Test files.
MATCH_PATH = 'match/'
ACTIONS_PATH = 'actions/'
SET_FIELD_PATH = 'actions/25_SET_FIELD/'
OPTION_PATH = 'actions/optional/'
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

test_dir = OUT_DIR + OPTION_PATH
if not os.path.isdir(test_dir):
    os.system('mkdir %s' % test_dir)

convert_files(IN_DIR)
print 'Finished. Out directory = %s' % OUT_DIR
