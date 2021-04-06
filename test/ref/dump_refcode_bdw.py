#!/usr/bin/env python
import sys
import r2pipe
from dumpbin import R2BinaryDumper
from dumpbin_util import getReloc

if __name__ == "__main__":
    r2 = r2pipe.open(sys.argv[1])
    r2dumpbin = R2BinaryDumper(r2, ["f va @ 0"])
    r2dumpbin.setReloc(getReloc(sys.argv[2]))
    r2dumpbin.run_tool('aa') # pi command will get wrong after 'aaaa'
