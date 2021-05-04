#!/usr/bin/env python
# dumps Ivy Bridge and Haswell mrc.bin with the following SHA256 checksums
# systemagent-r6.bin: a8aeaa2d9f84ebe9d78a464b881670d20bc78e38c44da56d9b44e2782c4777ad
# haswell.bin: d368ba45096a3b5490ed27014e1f9004bc363434ffdce0c368c08a89c4746722

import sys
import r2pipe
from dumpbin import R2BinaryDumper

if __name__ == "__main__":
    r2 = r2pipe.open(sys.argv[1])
    r2dumpbin = R2BinaryDumper(r2)
    r2dumpbin.run_tool()
