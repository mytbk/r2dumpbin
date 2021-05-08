#!/usr/bin/env python
# Copyright (C)  2021 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT
#
# To dump a Win32 PE file with this tool, you need to install mingw libraries
# In Arch, install them with `pacman -S mingw-w64`

from dumpbin import R2BinaryDumper
from pe_import_resolv import r2_pe_import_info
from dumpbin_util import bytes_to_i32
import r2pipe
import sys
import logging

class R2PEDumper(R2BinaryDumper):
    def __init__(self, r2 = r2pipe.open()):
        super(R2PEDumper, self).__init__(r2, scripts = [])

    def init_tool(self):
        self.BaseAddr = self.r2.cmdj("ij")["bin"]["baddr"]
        self.addr_ranges = []
        self.code_ranges = []
        self.sections = {}
        addr_map = self.r2.cmdj("omj")
        for m in addr_map:
            section = m["name"]
            if section[0:5] in ["fmap.", "mmap."]:
                section = section[5:]

            if section == ".idata":
                continue

            if section == ".reloc":
                self.HasReloc = True
                self.process_pe_reloc(self.readBytes(m["from"],m["to"]-m["from"]+1))
                continue

            r = (m["from"],m["to"]+1)
            self.addr_ranges.append(r)
            if 'x' in m["perm"]:
                self.code_ranges.append(r)

            self.sections[m["from"]] = section

        for s,e in self.addr_ranges:
            logging.info("Address range: [0x{:08x},0x{:08x})".format(s,e))

        for s,e in self.code_ranges:
            logging.info("Code range: [0x{:08x},0x{:08x})".format(s,e))

        entries = self.r2.cmdj("iej")
        self.entries = [e["vaddr"] for e in entries]
        self.unsolved += self.entries

        self.pe_imports, _, self.pe_libs = r2_pe_import_info(self.r2)

        if self.HasReloc:
            logging.info("Found {} relocation addresses.".format(len(self.RelocAddr)))
            self.add_relocation_immref()

    def print_assembly(self, header_fmt):
        print(";; Generated with r2dumpbin (https://github.com/mytbk/r2dumpbin)\n")
        print("bits 32")
        for sym in self.pe_imports.values():
            print("extern {}".format(sym))

        print("; link flag and libs: " + '-e fcn_{:08x} '.format(self.entries[0]) +
              ' '.join(['-l' + l for l in self.pe_libs]))
        print("global fcn_{:08x}".format(self.entries[0]))

        for addr,endaddr in self.addr_ranges:
            print("\nsection", self.sections[addr])
            self.print_range(addr, endaddr, '')

    def process_pe_reloc(self,reloc_data):
        idx = 0
        while idx + 8 < len(reloc_data):
            page_rva = bytes_to_i32(reloc_data[idx:idx+4])
            block_size = bytes_to_i32(reloc_data[idx+4:idx+8])

            if block_size == 0 or idx + block_size > len(reloc_data):
                return

            logging.debug("Reloc block: page_rva = 0x{:08x}, size = {}.".
                          format(page_rva, block_size))

            bidx = idx + 8
            while bidx < idx + block_size:
                reloc_offset = ((reloc_data[bidx + 1] & 0xf) << 8) \
                    | reloc_data[bidx]
                reloc_type = reloc_data[bidx + 1] >> 4

                if reloc_type == 3:
                    reloc_addr = page_rva + reloc_offset
                    self.RelocAddr.add(reloc_addr)

                bidx = bidx + 2

            idx = idx + block_size
            logging.debug("Found {} relocs in total.".format(len(self.RelocAddr)))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        r2dumpbin = R2PEDumper(r2pipe.open(sys.argv[1]))
    else:
        r2dumpbin = R2PEDumper()

    r2dumpbin.run_tool()
