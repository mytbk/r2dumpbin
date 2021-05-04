#!/usr/bin/env python
# script used to dump samus mrc.bin
# SHA256: 96b15aae46f4ba8b59685b5b937350b31850ca400806ea4252ee5d749e780631

import sys
import r2pipe
from dumpbin import R2BinaryDumper

fcns = [0xfffa87da, 0xfffab07d, 0xfffb742b, 0xfffd295d]

if __name__ == "__main__":
    r2dumpbin = R2BinaryDumper(r2pipe.open(sys.argv[1]))
    for f in fcns:
        r2dumpbin.mark_function(f)
    r2dumpbin.run_tool()
