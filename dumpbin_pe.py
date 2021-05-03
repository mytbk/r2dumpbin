#!/usr/bin/env python
# Copyright (C)  2021 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT
#
# To dump a Win32 PE file with this tool, you need to install mingw libraries
# In Arch, install them with `pacman -S mingw-w64`

from dumpbin import R2BinaryDumper
from pe_import_resolv import r2_pe_import_info
import r2pipe
import sys

class R2PEDumper(R2BinaryDumper):
    def __init__(self, r2 = r2pipe.open()):
        super(R2PEDumper, self).__init__(r2, scripts = [])

    def init_tool(self):
        self.addr_ranges = []
        self.code_ranges = []
        addr_map = self.r2.cmdj("omj")
        for m in addr_map:
            r = (m["from"],m["to"])
            self.addr_ranges.append(r)
            if 'x' in m["perm"]:
                self.code_ranges.append(r)

        entries = self.r2.cmdj("iej")
        self.entries = [e["vaddr"] for e in entries]
        self.unsolved += self.entries

        self.pe_imports, _, self.pe_libs = r2_pe_import_info(self.r2)

    def print_assembly(self):
        print(";; Generated with r2dumpbin (https://github.com/mytbk/r2dumpbin)\n")
        print("bits 32")
        for sym in self.pe_imports.values():
            print("extern {}".format(sym))

        print("; link flag and libs: " + '-e fcn_{:08x} '.format(self.entries[0]) +
              ' '.join(['-l' + l for l in self.pe_libs]))

        for addr,_ in self.addr_ranges:
            self.print_range(addr)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r2dumpbin = R2PEDumper(r2pipe.open(sys.argv[1]))
    else:
        r2dumpbin = R2PEDumper()

    r2dumpbin.run_tool()
