#!/usr/bin/env python

import argparse
import datetime
import os
import re

from xml.dom import minidom

LOG_DIR = './log'
OUT_FILE = './result.html'

DATE_RE = '[0-9]{4}-[0-9]{2}-[0-9]{2} ' \
    + '[0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} \\[INFO\\] '


class TestResult(object):
    def __init__(self, logfile):
        stat = os.stat(logfile)
        last_modified = stat.st_mtime
        dtime = datetime.datetime.fromtimestamp(last_modified)
        self.file_name = os.path.basename(logfile)
        self.last_modified = dtime.strftime("%Y-%m-%d %H:%M:%S")
        ifile = open(logfile, 'r')
        lines = ifile.readlines()
        ifile.close()
        self.results = {}
        for line in lines:
            if '\033[' in line:
                line = re.sub(DATE_RE, '', line)
                line = re.sub('\\033\[[0-9]{1,2}m', '', line)
                line = line.replace('\n', '')
                (key, value_title) = line.split(' : ')
                if -1 != value_title.find(' '):
                    (value, title) = value_title.split(' ', 1)
                else:
                    value = value_title
                    title = None
                self.results[key] = {'value': value, 'title': title}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Create html file including the results of '
                    'of_tester.')
    parser.add_argument(
        '-l', '--log-dir', default=LOG_DIR, type=str,
        help='directory where the log files exist. '
             '(default: %s)' % LOG_DIR,
        dest='log_dir')
    parser.add_argument(
        '-o', '--out-file', default=OUT_FILE, type=str,
        help='output html file. (default: %s)' % OUT_FILE,
        dest='out_file')
    args = parser.parse_args()
    return args


def read_dir(path):
    files = sorted(os.listdir(path))
    results = []
    for logfile in files:
        if logfile.endswith('~'):
            continue
        result = TestResult(path + os.sep + logfile)
        results.append(result)
    return results


def make_keys(results):
    temp_keys = []
    for result in results:
        temp_keys.append(sorted(result.results))
    keys = max(temp_keys)
    return keys


def make_html(keys, results):
    doc = minidom.Document()
    html = doc.createElementNS('http://www.w3.org/1999/xhtml', 'html')
    html.setAttribute('xmlns', 'http://www.w3.org/1999/xhtml')
    doc.appendChild(html)
    head = doc.createElement('head')
    html.appendChild(head)
    title = doc.createElement('title')
    head.appendChild(title)
    title_text = doc.createTextNode('of_tester results')
    title.appendChild(title_text)
    style = doc.createElement('style')
    style.setAttribute('type', 'text/css')
    head.appendChild(style)
    css = """
    table, th, td { border: 1px #000000 solid; }
    td { text-align: center; }
    td.ok { background-color: #88ff88; }
    td.ng { background-color: #ff8888; }
    """
    style_text = doc.createComment(css)
    style.appendChild(style_text)
    body = doc.createElement('body')
    html.appendChild(body)
    table = make_table(keys, results, doc)
    body.appendChild(table)
    return doc


def make_table(keys, results, doc):
    table = doc.createElement('table')
    tre = doc.createElement('tr')
    table.appendChild(tre)
    the = doc.createElement('th')
    tre.appendChild(the)
    th_text = doc.createTextNode('file_name')
    the.appendChild(th_text)
    for result in results:
        the = doc.createElement('th')
        tre.appendChild(the)
        th_text = doc.createTextNode(result.file_name)
        the.appendChild(th_text)
    tre = doc.createElement('tr')
    table.appendChild(tre)
    tde = doc.createElement('td')
    tre.appendChild(tde)
    td_text = doc.createTextNode('last_modified')
    tde.appendChild(td_text)
    for result in results:
        comment = doc.createComment(result.file_name)
        tre.appendChild(comment)
        tde = doc.createElement('td')
        tre.appendChild(tde)
        td_text = doc.createTextNode(result.last_modified)
        tde.appendChild(td_text)
    for key in keys:
        tre = doc.createElement('tr')
        table.appendChild(tre)
        tde = doc.createElement('td')
        tre.appendChild(tde)
        td_text = doc.createTextNode(key)
        tde.appendChild(td_text)
        for result in results:
            comment = doc.createComment(result.file_name)
            tre.appendChild(comment)
            tde = doc.createElement('td')
            tre.appendChild(tde)
            value_title = result.results.get(key)
            if value_title:
                td_text = doc.createTextNode(value_title['value'])
                if 'OK' == value_title['value']:
                    tde.setAttribute('class', 'ok')
                else:
                    tde.setAttribute('class', 'ng')
                tde.appendChild(td_text)
                if value_title['title'] is not None:
                    tde.setAttribute('title', value_title['title'])
    return table


def write_html(outfile, doc):
    ofile = open(outfile, 'w')
    ofile.write(doc.toprettyxml())
    ofile.close()


def main():
    args = parse_args()
    results = read_dir(args.log_dir)
    keys = make_keys(results)
    doc = make_html(keys, results)
    write_html(args.out_file, doc)


if '__main__' == __name__:
    main()
