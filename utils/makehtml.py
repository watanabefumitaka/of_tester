#!/usr/bin/env python

import argparse
import datetime
import os
import re

from xml.dom import minidom


TEST_START_LOG = '--- Test start ---'
LOG_DIR = './log'
OUT_FILE = './result.html'

DATE_RE = '[0-9]{4}-[0-9]{2}-[0-9]{2} ' \
    + '[0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} \[INFO\] '

class TestResult(object):
    def __init__(self, logfile):
        stat = os.stat(logfile)
        last_modified = stat.st_mtime
        dt = datetime.datetime.fromtimestamp(last_modified)
        self.file_name = os.path.basename(logfile)
        self.last_modified = dt.strftime("%Y-%m-%d %H:%M:%S")
        f = open(logfile, 'r')
        lines = f.readlines()
        f.close()
        num = 0
        for line in lines:
            if TEST_START_LOG in line:
                break
            num += 1
        lines = lines[num:]
        self.results = {}
        for line in lines:
            if '\033[' in line:
                line = re.sub(DATE_RE, '', line)
                line = re.sub('\\033\[[0-9]{1,2}m', '', line)
                line = line.replace('\n', '')
                (key, value) = line.split(' : ')
                self.results[key] = value


def main():

    parser = argparse.ArgumentParser(
        description='Create html file including the results of of_tester.')
    parser.add_argument(
        '-l', '--log-dir', default=LOG_DIR, type=str,
        help='directory where the log files exist. (default: %s)' % LOG_DIR,
        dest='log_dir')
    parser.add_argument(
        '-o', '--out-file', default=OUT_FILE, type=str,
        help='output html file. (default: %s)' % OUT_FILE,
        dest='out_file')
    args = parser.parse_args()

    files = os.listdir(args.log_dir)

    results = []
    for file in files:
        result = TestResult(LOG_DIR + os.sep + file)
        results.append(result)

    temp_keys = []
    for result in results:
        temp_keys.append(sorted(result.results))
    keys = max(temp_keys)

    dom = minidom.getDOMImplementation()
    doc = dom.createDocument(None, "html", None)
    html = doc.documentElement
    body = doc.createElement('body')
    html.appendChild(body)
    table = doc.createElement('table')
    body.appendChild(table)
    tr = doc.createElement('tr')
    table.appendChild(tr)
    th = doc.createElement('th')
    tr.appendChild(th)
    th_text = doc.createTextNode('file_name')
    th.appendChild(th_text)
    for result in results:
        th = doc.createElement('th')
        tr.appendChild(th)
        th_text = doc.createTextNode(result.file_name)
        th.appendChild(th_text)
    tr = doc.createElement('tr')
    table.appendChild(tr)
    td = doc.createElement('td')
    tr.appendChild(td)
    td_text = doc.createTextNode('last_modified')
    td.appendChild(td_text)
    for result in results:
        td = doc.createElement('td')
        tr.appendChild(td)
        td_text = doc.createTextNode(result.last_modified)
        td.appendChild(td_text)
    for key in keys:
        tr = doc.createElement('tr')
        table.appendChild(tr)
        td = doc.createElement('td')
        tr.appendChild(td)
        td_text = doc.createTextNode(key)
        td.appendChild(td_text)
        for result in results:
            td = doc.createElement('td')
            tr.appendChild(td)
            td_text = doc.createTextNode(result.results.get(key, '&nbsp;'))
            td.appendChild(td_text)

    f = open(args.out_file, 'w')
    f.write(doc.toprettyxml())
    f.close()


if '__main__' == __name__:
    main()
