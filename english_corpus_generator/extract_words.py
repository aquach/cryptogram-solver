#!/usr/bin/python2.7

import glob
import os
import re
import sys

files = glob.glob('pages/*')

words = []
for filename in files:
    page = open(filename).read()
    for match in re.finditer(r'<tr>\n<td>([0-9]+)</td>\n<td><a[^>]*>([^<]*)</a></td>', page):
        words.append((int(match.group(1)), match.group(2)))

words.sort(key=lambda word: word[0])

out = open('corpus.txt', 'w')
out.write('\n'.join([word[1] for word in words]))
