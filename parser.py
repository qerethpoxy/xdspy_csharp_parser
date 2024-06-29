# coding: utf-8

import argparse
from bs4 import BeautifulSoup, CData
import re
import rich


def decode(key, encoded_text):
    decoded_text = ''
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    for char in encoded_text:
        index = charset.find(char)
        index = (index - key + 65 if index - key < 0 else index - key) % 65
        decoded_text += charset[index]
    return decoded_text


def parse_params(blob):
    taskname, *parts = blob.split(' ')
    
    return taskname, _
    #match = re.search(r'(?P<key>\w+)=\"(?P<value>[\da-f]+)\"', blob, re.I)
    #return match.group('key'), match.group('value')


def parse(content):
    tasks = {}
    soup = BeautifulSoup(content, 'html.parser')

    utask, *blobs = soup.find_all('usingtask')

    # parse UTask
    utask = {
        'taskname': utask['taskname'],
        'factory': utask['taskfactory'],
        'assemblyfile': utask['assemblyfile'],
        'type': utask.task.code['type'],
        'language': utask.task.code['language'],
        'code': utask.task.code.find(string=lambda tag: isinstance(tag, CData)).string.strip(),
    }

    # parse others tasks
    for blob in blobs:
        tasks[blob['taskname']] = {
            'assemblyfile': blob['assemblyfile'],
        }

    # parse params
    for blob in re.findall(r'&lt;(?P<params>[\w\s=\"]+)/&gt;', str(soup.find('target')), re.I):
        taskname, *items = blob.split(' ')
        tasks[taskname]['params'] = {}
        for item in items[:-1]:
            m = re.search(r'(?P<key>\w+)=\"(?P<value>[\da-f]+)\"', item, re.I)
            tasks[taskname]['params'][m.group('key')] = m.group('value')

    return tasks

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('path', type=str, help='malicious file')
    args = argparser.parse_args()

    with open(args.path) as file:
        content = file.read()

    result = parse(content)
    rich.print(result)
