import json
import os
from xlwt import Workbook

IN_DIR = '../tests/'


def convert_files(path, test_list):
    if os.path.isdir(path):  # Directory
        for test_path in os.listdir(path):
            test_path = path + (test_path if path[-1:] == '/'
                                else '/%s' % test_path)
            test_list = convert_files(test_path, test_list)

    elif os.path.isfile(path):  # File
        (dummy, ext) = os.path.splitext(path)
        if ext == '.json':
            buf = open(path, 'rb').read()
            json_buf = json.loads(buf)
            test_list.update(get_data(path, json_buf))

    return test_list

def get_data(path, json_buf):
    def __pkt_list_tostr(pkt, key):
        return '%s:\n ' % key + ',\n '.join(pkt[key])

    data_key = path.rstrip('.json').replace('../', '')
    data = {data_key: {}}
    for i, test in enumerate(json_buf):
        desc = test['description'].split(':', 1)[1].rsplit(' packet=')[0]
        packets = []
        for pkt in test['tests']:
            if 'ingress' in pkt:
                packets.append(__pkt_list_tostr(pkt, 'ingress'))
            if 'egress' in pkt:
                packets.append(__pkt_list_tostr(pkt, 'egress'))
            if 'PACKET_IN' in pkt:
                packets.append(__pkt_list_tostr(pkt, 'PACKET_IN'))
            if 'table-miss' in pkt:
                p = 'table-miss:\n '                
                p += ',\n '.join([str(a) for a in pkt['table-miss']])
                packets.append(p)

        data[data_key]['test%02d' % i] = {'desc': desc, 'pkts': packets}

    return data



test_list = convert_files(IN_DIR, {})

wb = Workbook()
ws = wb.add_sheet( "test_list" )
ws.write( 0, 0, "test file" )
ws.write( 0, 1, "test number" )
ws.write( 0, 2, "description" )
ws.write( 0, 3, "test packets" )

keys = test_list.keys()
keys.sort()

row = 1
for key in keys:
    test_data = test_list[key]
    test_keys = test_data.keys()
    test_keys.sort()
    flg = True
    for test_key in test_keys:
        if flg:
            ws.write(row, 0, key)
            flg = False
        ws.write(row, 1, test_key)
        ws.write(row, 2, test_data[test_key]['desc'])
        column = 3
        for pkt in test_data[test_key]['pkts']:
            ws.write(row, column, pkt)
            column += 1
        row += 1

wb.save( "test_list.xls" )
