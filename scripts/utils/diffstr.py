#!/usr/bin/env python3

from itertools import cycle, zip_longest
from sys import argv, stdin

Red = "\x1b[91m"
Green = "\x1b[92m"
Yellow = "\x1b[93m"
Blue = "\x1b[94m"
Magenta = "\x1b[95m"
Cyan = "\x1b[96m"
Reset = "\x1b[0m"

COLORS = cycle([Red, Green, Yellow, Blue, Magenta, Cyan])

def colorize(s, c):
    return '%s%s%s' % (c, s, Reset)

def print_diff(s1, s2):
    line = ''
    color = next(COLORS)
    for c1, c2 in zip_longest(s1, s2):
        if c1 is None:
            line += c2
        elif c2 is None:
            break
        elif c1 == c2:
            line += c2
        elif c1 != c2:
            line += colorize(c2, color)
    print(line)

if len(argv) == 1:
    f = stdin
else:
    f = open(argv[1])

line1 = f.readline().strip()
print(line1)
while True:
    line2 = f.readline().strip()
    if not line2:
        break 
    print_diff(line1, line2)
    line1 = line2
