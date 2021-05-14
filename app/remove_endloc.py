#!/usr/bin/env python

import sys

def remove_endloc(fn):
    with open(fn,'r') as f:
        for L in f:
            if L[0:7] == "endloc_":
                skip = True
            elif ':' in L or "section " in L:
                skip = False

            if not skip:
                print(L.strip())

if __name__ == "__main__":
    remove_endloc(sys.argv[1])
