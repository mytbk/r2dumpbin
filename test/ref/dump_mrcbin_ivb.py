#!/usr/bin/env python
import sys
import r2pipe
from dumpbin import R2BinaryDumper

if __name__ == "__main__":
    r2 = r2pipe.open(sys.argv[1])
    r2.cmd("f fcn1 @ 0xfffb8dbb")
    r2dumpbin = R2BinaryDumper(r2)
    r2dumpbin.run_tool()
