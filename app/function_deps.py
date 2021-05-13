#!/usr/bin/env python

import sys
import re

ref_re = re.compile('ref_[a-zA-Z0-9]+')
loc_re = re.compile('loc_[a-zA-Z0-9]+')
fcn_re = re.compile('fcn_[a-zA-Z0-9]+')

'''
scan the whole asm file for all the labels starting with fcn_
find the dependencies of a function

function info is func_name->extern_labels
'''

def scan_file(fn):
    function_info = dict()
    with open(fn, 'r') as f:
        in_function = False
        for L in f:
            # remove the line comment
            sc = L.find(';')
            if sc >= 0:
                L = L[:sc]

            L = L.strip()
            if len(L) == 0:
                continue

            if L[-1] == ':':
                # label found
                label = L[:-1]
                if label[0:4] == 'fcn_':
                    in_function = True
                    function_name = label
                    function_info[label] = set()
                    function_labels = set()
                elif label[0:4] == 'loc_':
                    if in_function:
                        function_labels.add(label)
                        if label in function_info[function_name]:
                            function_info[function_name].remove(label)
                elif label[0:4] == 'ref_' or label[0:7] == 'endloc_':
                    in_function = False

                continue

            hasRef = False
            ref = ref_re.search(L)
            if ref is not None:
                hasRef = True
                s,e = ref.span()

            fcn = fcn_re.search(L)
            if fcn is not None:
                hasRef = True
                s,e = fcn.span()

            loc = loc_re.search(L)
            if loc is not None:
                hasRef = True
                s,e = loc.span()

            if hasRef:
                label = L[s:e]
                if in_function and not label in function_labels:
                    function_info[function_name].add(label)

    return function_info

if __name__ == "__main__":
    print(scan_file(sys.argv[1]))
