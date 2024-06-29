# coding: utf-8

import argparse
from base64 import b64decode
from bs4 import BeautifulSoup, CData, Comment
from dotnetfile import DotNetPE
import hashlib
from pathlib import PureWindowsPath
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

def parse(content):
    tasks = {}
    soup = BeautifulSoup(content, 'html.parser')

    code, *encoded_assemblies = soup.find_all(string=lambda tag: isinstance(tag, Comment))

    # parse  batch
    batch = '\n'.join(line for line in code.splitlines()[1:] if not line.startswith('::'))

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
            'filename': blob['assemblyfile'],
        }

    # parse task params
    for blob in re.findall(r'&lt;(?P<params>[\w\s=\"]+)/&gt;', str(soup.find('target')), re.I):
        taskname, *items = blob.split(' ')
        tasks[taskname]['params'] = {}
        for item in items[:-1]:
            m = re.search(r'(?P<key>\w+)=\"(?P<value>[\da-f]+)\"', item, re.I)
            tasks[taskname]['params'][m.group('key')] = m.group('value')

    # parse assemblies
    for blob in encoded_assemblies:
        parts = blob.split(':')
        if len(parts) == 2:
            path = b64decode(parts[0]).decode('utf-8')
            assembly = b64decode(parts[1])

        parts = blob.split('#')
        if len(parts) == 3:
            key = int(parts[0])
            encoded_path = parts[1]
            encoded_assembly = parts[2]
            path = b64decode(decode(key, encoded_path)).decode('utf-8')
            assembly = b64decode(decode(key, encoded_assembly))

        sha1 = hashlib.sha1()
        sha1.update(assembly)

        dotnet_file = DotNetPE(assembly)

        for task in tasks.values():
            if task['filename'] == PureWindowsPath(path).name:
                task.update({
                    'path': path,
                    'sha1': sha1.hexdigest(),
                    'assembly_name': dotnet_file.Assembly.get_assembly_name(),
                })
    
    return batch, utask, tasks


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('path', type=str, help='malicious file')
    args = argparser.parse_args()

    with open(args.path) as file:
        content = file.read()

    batch, utask, tasks = parse(content)
    print(batch)
    print(utask)
    rich.print(tasks)
