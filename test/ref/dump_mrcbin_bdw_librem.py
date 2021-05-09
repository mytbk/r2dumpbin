#!/usr/bin/env python
# script used to dump librem mrc.bin
# SHA256: dd05ab481e1fe0ce20ade164cf3dbef3c479592801470e6e79faa17624751343

import sys
import r2pipe
from dumpbin import R2BinaryDumper

fcns = [0xfffb00f4, 0xfffb014c, 0xfffb7ea0, 0xfffd2c4f]

if __name__ == "__main__":
    r2dumpbin = R2BinaryDumper(r2pipe.open(sys.argv[1]))
    for f in fcns:
        r2dumpbin.mark_function(f)
    r2dumpbin.run_tool()
