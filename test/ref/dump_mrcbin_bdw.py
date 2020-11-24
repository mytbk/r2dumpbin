#!/usr/bin/env python
# script used to dump samus mrc.bin

import sys
import r2pipe
from dumpbin import R2BinaryDumper

scripts = [
    "f va @ 0xfffa0000",
    "f fcn1 @ 0xfffa87da",
    "f fcn2 @ 0xfffb7579",
    "f fcn3 @ 0xfffab07d",
    "f fcn4 @ 0xfffb742b",
    "f fcn5 @ 0xfffb7458",
    "f fcn6 @ 0xfffd295d"]

if __name__ == "__main__":
    r2dumpbin = R2BinaryDumper(r2pipe.open(sys.argv[1]), scripts)
    r2dumpbin.run_tool()
