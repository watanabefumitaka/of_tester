import base64
import codecs
import json
import os
from ryu.lib.packet import packet


IN_DIR = '../tests/'
OUT_DIR = '../new_tests/'


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
            convert_file(path, json_buf)


def convert_file(path, json_buf):

    for i, buf in enumerate(json_buf):
        flg = False
        if 'packets' in buf:
            for pkt in buf['packets']:
                if 'egress' in pkt or 'PACKET_IN' in pkt:
                    flg = True
                    break
        if not flg:
            tbls = ([0] if 'target_tables' not in json_buf[i]
                    else json_buf[i]['target_tables'])
            json_buf[i]['packets'][0]['table-miss'] = tbls
            if 'target_tables' in json_buf[i]:
                del json_buf[i]['target_tables']

        json_buf[i]['tests'] = json_buf[i]['packets']
        del json_buf[i]['packets']

        json_buf[i]['prerequisite'] = json_buf[i]['FLOW_MOD']
        del json_buf[i]['FLOW_MOD']
            


    path = OUT_DIR + path[len(IN_DIR):]
    with codecs.open(path, 'w', "utf-8") as f:
        json.dump(json_buf, f, sort_keys=True, indent=4, ensure_ascii=False, separators=(',',':'))

    f = open(path, "a")
    f.write('\n')
    f.close()


convert_files(IN_DIR)
