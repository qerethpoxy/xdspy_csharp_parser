# coding: utf-8

import argparse
from base64 import b64decode
from bs4 import BeautifulSoup, CData, Comment
from dotnetfile import DotNetPE
import hashlib
import re


def parse(content):
    pass


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('path', type=str, help='malicious file')
    args = argparser.parse_args()

    with open(args.path) as file:
        content = file.read()

    parse(content)
