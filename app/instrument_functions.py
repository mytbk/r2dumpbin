#!/usr/bin/env python

import sys

'''
instrument on all functions, to make them print out their name when called
'''

def instrument_file(fn):
    functions = []
    for L in open(fn, 'r'):
        line_orig = L.strip()

        # remove asm comment
        i = line_orig.find(';')
        if i != -1:
            line = line_orig[0:i].strip()
        else:
            line = line_orig

        print(line_orig)
        if line[0:4] == "fcn_" and line[-1] == ":":
            fname = line[0:-1]
            print('push ' + fname + '_name')
            print('call print_func')
            print('add esp, 4')
            functions.append(fname)

    for f in functions:
        print('extern ' + f + '_name')

    for f in functions:
        print('const char ' + f + '_name[] = "' + f + '\\n";')


if __name__ == '__main__':
    instrument_file(sys.argv[1])
