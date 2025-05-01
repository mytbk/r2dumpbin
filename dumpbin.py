#!/usr/bin/env python
# Copyright (C)  2018 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT
#
# A radare2 Python script to dump a raw IA32 binary
# to an NASM source file
#
# usage:
# $ r2 mrc.bin
# [0x00000000]> f va @ 0xfffa0000
# [0x00000000]> . dumpbin.py > mrc.asm
#
# Then you can run `nasm mrc.asm` to generate a binary
# called mrc which is identical to mrc.bin

try:
    raise RuntimeError("TODO: rizin and rzpipe is not supported yet")
    import rzpipe as r2pipe
    Reloc_Cmd = "omb."
    Flag_List_Cmd = "flj"
except:
    import r2pipe
    # r2 relocate command changes between versions, so find the command first
    r2test = r2pipe.open("malloc://512")
    Reloc_Cmd = r2test.cmd("om?~relocate current map").split(' ')[1]
    r2test.quit()
    Flag_List_Cmd = "fj"

import re
import logging
from dumpbin_util import *
from arch_x86 import asmfixup

logging.basicConfig(level=logging.INFO)

asmlog = logging.getLogger('asm')
asmlog.setLevel(logging.INFO)

alog = logging.getLogger('analysis')
alog.setLevel(logging.INFO)

Aggresive = 2


class R2BinaryDumper:
    def __init__(self, r2=None, scripts=["f va @ 0xfffa0000"]):
        if r2 is None:
            self.r2 = r2pipe.open()
        else:
            self.r2 = r2

        # RelocAddr: image offset that have data to be relocated
        # ptr[i] = BaseAddr+RelocAddr[i], *(ptr[i]) += BaseAddr
        # To avoid modifying the relocated addresses *(ptr[i]), we leave the
        # binaries at its original base address, i.e.:
        # - For refcode.elf, BaseAddr = 0
        # - For relocatable PE, BaseAddr = image base
        self.RelocAddr = set()
        self.unsolved = []
        self.speculate = set()
        self.speculate_set = set()
        self.solved = set()
        # end addresses of code blocks
        self.endaddrs = set()
        self.immref = set()
        self.jumptab = set()
        self.functions = set()
        self.str_dict = dict()
        self.non_function_labels = set()
        # labels that needs to be adjusted because they split a pointer
        # we move the label to a higher address, and store this label in
        # label_adjust map, where label_adjuct[lab] = adjusted_lab and
        # the added offset is (adjusted_lab - lab)
        self.label_adjust = dict()
        # mark pointers in data blocks: First we find all the possible
        # pointers. After the immrefs are all found, we use
        # min_block_pointer_portion to check if there're enough
        # pointers in a data block.
        self.pointer_map = dict()
        self.pointers = set()
        self.min_block_pointer_portion = 1.0/3
        self.SpecMode = False
        self.HasReloc = False
        self.code_ranges = []
        self.addr_ranges = []
        # pe_imports map: address -> DLL import symbol
        self.pe_imports = {}

        for s in scripts:
            r2.cmd(s)

    def mark_function(self, fcn):
        self.unsolved.append(fcn)
        self.functions.add(fcn)

    def find_and_mark_functions(self, analyze = 'aaaa'):
        self.r2.cmd(analyze)
        fcns = self.r2.cmdj("aflj")
        for f in fcns:
            self.mark_function(f["offset"])

    def get_insns(self, addr):
        return self.r2.cmdj("pij 10 @ {}".format(addr))

    def read32(self, addr):
        Bytes = self.r2.cmdj("xj 4 @ {}".format(addr))
        val = bytes_to_i32(Bytes)
        return val

    def readBytes(self, addr, l):
        return self.r2.cmdj("xj {} @ {}".format(l, addr))

    def setReloc(self, relocAddrs):
        self.HasReloc = True
        self.RelocAddr.update(relocAddrs)
        logging.info("Found {} relocation addresses.".format(len(self.RelocAddr)))

    def add_relocation_immref(self):
        for addr in self.RelocAddr:
            # the data stored at ref_addr is the original data when
            # the binary is loaded at the default base
            rptr = self.BaseAddr + addr
            ref_addr = self.read32(rptr)
            self.immref.add(ref_addr)
            logging.debug("Add immref 0x{:08x} due to relocation from 0x{:08x}."
                          .format(ref_addr,rptr))

    def in_addr_range(self, addr):
        for r in self.addr_ranges:
            start, end = r
            if addr >= start and addr < end:
                return True

        return False

    def in_code_range(self, addr):
        for (start,end) in self.code_ranges:
            if addr >= start and addr < end:
                return True

        return False

    def init_tool(self):
        self.r2.cmd("e asm.bits=32")

        self.BaseAddr = 0
        self.FileSize = self.r2.cmdj("ij")["core"]["size"]
        EndAddr = self.FileSize

        Flags = self.r2.cmdj(Flag_List_Cmd)
        for f in Flags:
            if f["name"] == "va":
                self.BaseAddr = f["offset"]
                self.r2.cmd("{} {}".format(Reloc_Cmd, self.BaseAddr))
                self.r2.cmd("s {}".format(self.BaseAddr))
                EndAddr = self.BaseAddr + self.FileSize
            elif "reloc:" in f["name"]:
                reloc_file = f["name"][6:]
                logging.info("Found reloc file {}.".format(reloc_file))
                self.setReloc(getReloc(reloc_file))
            elif "fcn" in f["name"]:
                # support manually marked functions
                fcn = f["offset"]
                self.mark_function(fcn)

        self.addr_ranges.append((self.BaseAddr, EndAddr))
        self.code_ranges.append((self.BaseAddr, EndAddr))

        self.unsolved.append(self.BaseAddr)

        if self.HasReloc:
            self.add_relocation_immref()

    def isRelocInsn(self, offset, size):
        for i in range(0, size):
            _addr = offset - self.BaseAddr + i
            if _addr in self.RelocAddr:
                return True

        return False

    def findX86FuncProlog(self, cur):
        Bytes = self.r2.cmdj("xj 256 @ {}".format(cur))
        if Bytes[0:3] == [0x55, 0x89, 0xe5]:  # push ebp; mov ebp, esp
            self.speculate.add(cur)
            self.functions.add(cur)
            return True
        elif Aggresive >= 1 and Bytes[0] == 0x55 and hasSubList(Bytes[1:10], [0x89, 0xe5]):
            # push ebp; ... ; mov ebp, esp
            self.speculate.add(cur)
            self.functions.add(cur)
            return True
        elif Aggresive >= 2 and Bytes[0] == 0x55 and hasSubList(Bytes[1:20], [0x89, 0xe5]):
            # push ebp; ... ; mov ebp, esp
            self.speculate.add(cur)
            self.functions.add(cur)
            return True
        elif Aggresive >= 9 and Bytes[0] == 0x55:  # just a push ebp
            self.speculate.add(cur)
            self.functions.add(cur)
            return True

        return False

    def analyze_functions(self):
        while len(self.unsolved) > 0 or len(self.speculate) > 0:
            # There are no unsolved addresses, so all the direct functions are
            # analyzed. Then we analyze indirect functions in the speculate set.
            if len(self.unsolved) == 0:
                self.unsolved = list(self.speculate.difference(self.solved))
                self.speculate.clear()
                self.SpecMode = True
                if len(self.unsolved) == 0:
                    break

                alog.debug("Analyze indirect functions.")

            cur = self.unsolved[0]
            eob = False

            if cur in self.solved:
                del(self.unsolved[0])
                continue

            if self.SpecMode:
                self.speculate_set.add(cur)

            alog.debug("Analyzing {:08x}".format(cur))

            while not eob:
                insns = self.get_insns(cur)

                for insn in insns:
                    if not self.in_code_range(cur):
                        eob = True
                        break

                    if cur in self.solved:
                        eob = True
                        break

                    if insn["type"] == "invalid":
                        eob = True
                        break

                    cur += insn["size"]

                    if insn["type"] in ["and", "or", "xor"] and not insn["refptr"]:
                        # it's very rare to do bitwise operation on a reference
                        pass
                    else:
                        if insn.get("val") is not None and \
                                not self.HasReloc and \
                                self.in_addr_range(insn["val"]):
                            alog.debug("reference @pc=0x%08x to 0x%08x", insn["offset"], insn["val"])
                            self.immref.add(insn["val"])

                        # since now many instructions don't have "ptr" attribute
                        # we need to match the disasm
                        disasm = insn["opcode"]
                        # [... + 0x...]
                        m = re.search("\\+ 0x[0-9a-fA-F]+\\]", disasm)
                        if m is not None:
                            asmlog.debug(disasm)
                            ptr = int(disasm[m.start() + 4:m.end() - 1], 16)
                        else:
                            # [... - 0x...]
                            m = re.search("- 0x[0-9a-fA-F]+\\]", disasm)
                            if m is not None:
                                asmlog.debug(disasm)
                                ptr = int(
                                    disasm[m.start() + 4:m.end() - 1], 16)
                                ptr = (1 << 32) - ptr
                            else:
                                # [0x...]
                                m = re.search("\\[0x[0-9a-fA-F]+\\]", disasm)
                                if m is not None:
                                    asmlog.debug(disasm)
                                    ptr = int(
                                        disasm[m.start() + 3:m.end() - 1], 16)
                                else:
                                    ptr = None

                        if ptr is not None and not self.HasReloc and \
                                self.in_addr_range(ptr):
                            alog.debug("reference @pc=0x%08x to 0x%08x", insn["offset"], ptr)
                            self.immref.add(ptr)

                    if insn["type"] == "ret":
                        eob = True
                        break

                    if insn["type"] == "jmp":
                        alog.debug("jump from 0x%08x to 0x%08x", insn["offset"], insn["jump"])
                        self.unsolved.append(insn["jump"])
                        eob = True
                        break

                    # find jump/call table
                    if insn["type"] in ["ujmp", "ucall"] and ptr is not None:
                        if not self.HasReloc and self.in_addr_range(ptr):
                            search_jumptab = True
                        elif self.HasReloc and ptr in self.immref:
                            # when there is relocation, the jump table address should be calculated
                            # and added to immref
                            search_jumptab = True
                        else:
                            search_jumptab = False

                        if search_jumptab:
                            self.immref.add(ptr)
                            self.jumptab.add(ptr)
                            alog.debug("jump table reference @pc=0x%08x to 0x%08x", insn["offset"], ptr)
                            cur_ptr = ptr
                            while True:
                                loc = self.read32(cur_ptr)
                                if not self.HasReloc and self.in_code_range(loc):
                                    self.unsolved.append(loc)
                                elif self.HasReloc and cur_ptr-self.BaseAddr in self.RelocAddr \
                                     and self.in_code_range(loc):
                                    # the jump target in a relocatable file should also be stored at the
                                    # reloacted address
                                    self.unsolved.append(loc)
                                else:
                                    break

                                alog.debug("%s@%08x target is 0x%08x", insn["type"], insn["offset"], loc)
                                cur_ptr += 4
                                if insn["type"] == "ucall":
                                    self.functions.add(loc)

                    if insn["type"] == "ujmp":
                        eob = True
                        break

                    if insn["type"] == "cjmp":
                        alog.debug("conditional jump from 0x%08x to 0x%08x", insn["offset"], insn["jump"])
                        self.unsolved.append(insn["jump"])

                    if insn["type"] == "call":
                        alog.debug("call from 0x%08x to 0x%08x", insn["offset"], insn["jump"])
                        self.unsolved.append(insn["jump"])
                        self.functions.add(insn["jump"])

            self.endaddrs.add(cur)

            # try to continue disassembling a possible function
            # search to a 4-byte boundary
            while True:
                hasFunc = self.findX86FuncProlog(cur)
                if hasFunc:
                    break

                if cur % 4 == 0:
                    break
                else:
                    cur += 1

            self.solved.add(self.unsolved[0])
            del(self.unsolved[0])

        self.non_function_immref = self.immref.difference(self.solved)

        logging.info("Complete analyzing functions.")
        logging.info("{} locations to be printed.".format(len(self.solved)))

    def analyze_immref(self, addr, endaddr):
        alog.info("Analyze data references @ 0x{:x}.".format(addr))
        cur = addr
        eob = True
        while cur < endaddr:
            if cur in self.solved:
                eob = False

            if eob:
                end_of_bytes = cur + 1
                while end_of_bytes < endaddr and end_of_bytes not in self.solved \
                      and end_of_bytes not in self.endaddrs:
                    end_of_bytes = end_of_bytes + 1

                num_bytes = end_of_bytes - cur
                bytes_to_analyze = self.readBytes(cur, num_bytes)
                cur_ptr = cur
                while cur_ptr + 3 < end_of_bytes:
                    offset = cur_ptr - cur
                    val32 = bytes_to_i32(bytes_to_analyze[offset:offset+4])
                    if not self.HasReloc and self.in_addr_range(val32):
                        if not val32 in self.solved:
                            self.non_function_immref.add(val32)

                        alog.debug("Find immref to 0x{:08x}@0x{:08x}".format(val32,cur_ptr))
                        self.pointer_map[cur_ptr] = val32
                        cur_ptr = cur_ptr + 4
                    else:
                        cur_ptr = cur_ptr + 1

                cur = end_of_bytes
                continue

            else:  # not eob
                insns = self.get_insns(cur)
                for insn in insns:
                    if insn["type"] == "invalid":
                        break

                    cur += insn["size"]
                    if cur in self.solved or cur in self.endaddrs:
                        eob = True
                        break

        logging.info("{} non function immediate references.".format(
            len(self.non_function_immref)))

    def analyze_ascii_strings(self):
        logging.info("Searching for ASCII strings.")

        ref_list = list(self.non_function_immref)
        for _,end_addr in self.addr_ranges:
            ref_list.append(end_addr)

        ref_list.sort()

        for idx in range(0, len(ref_list) - 1):
            addr = ref_list[idx]
            dist = ref_list[idx + 1] - addr
            if dist < 4 or dist > 200:
                continue

            Bytes = self.r2.cmdj("xj {} @ {}".format(dist, addr))
            alog.debug(
                "dist = {}, addr = {}, Bytes = {}".format(dist, addr, Bytes))
            if goodString(Bytes):
                self.str_dict[addr] = (toString(Bytes), dist)

        logging.info("{} ASCII strings found.".format(len(self.str_dict)))

    def scan_labels(self):
        # a quick print pass to find all non function assembly labels,
        # thus avoid printing invalid non_function_immref items
        self.non_function_labels = set()
        for addr,endaddr in self.addr_ranges:
            self.scan_labels_range(addr,endaddr)

    def scan_labels_range(self,startaddr,endaddr):
        cur = startaddr
        eob = True

        labels = []
        while cur < endaddr:
            if cur in self.solved:
                labels.append(cur)
                eob = False
            elif cur in self.non_function_immref:
                labels.append(cur)
                self.non_function_labels.add(cur)
                alog.debug("Add non-function label @0x{:08x}.".format(cur))

            if eob:
                cur = cur + 1
                continue

            insns = self.get_insns(cur)
            for insn in insns:
                if insn["type"] == "invalid":
                    break

                cur += insn["size"]

                if cur in self.solved or cur in self.endaddrs:
                    eob = True
                    break

        # We collect the possible pointers after finding all the labels
        labels.append(endaddr)
        blocks = []
        for i in range(len(labels) - 1):
            if labels[i] in self.non_function_labels:
                blocks.append((labels[i], labels[i+1]))

        for b_start, b_end in blocks:
            bsize = b_end - b_start
            ptrs = set()
            for addr in range(b_start, b_end):
                if addr in self.pointer_map:
                    ptrs.add(addr)

            if len(ptrs) * 4 >= bsize * self.min_block_pointer_portion:
                alog.debug("{} pointers in block @0x{:08x}, add to the pointer set."
                           .format(len(ptrs), b_start))
                self.pointers.update(ptrs)

        # adjust labels to avoid pointer split
        for addr in range(startaddr, endaddr):
            hasPtr = False
            if self.HasReloc and addr-self.BaseAddr in self.RelocAddr:
                hasPtr = True
            elif not self.HasReloc and addr in self.pointers:
                hasPtr = True

            if hasPtr:
                for i in range(addr + 1, addr + 4):
                    if i in self.non_function_labels:
                        self.label_adjust[i] = addr + 4
                        self.non_function_labels.remove(i)
                        self.non_function_labels.add(addr + 4)
                        if i in self.jumptab:
                            self.jumptab.remove(i)
                            self.jumptab.add(addr + 4)


    def print_assembly(self, header_fmt):
        print(";; Generated with r2dumpbin (https://github.com/mytbk/r2dumpbin)\n")
        print("bits 32")
        for addr,endaddr in self.addr_ranges:
            self.print_range(addr,endaddr,header_fmt)

    def print_range(self, addr, endaddr, header_fmt):
        cur = addr
        eob = True
        nsolved = 0

        if len(header_fmt) > 0:
            print(header_fmt.format(addr))

        while cur < endaddr:
            if cur in self.solved:
                if cur in self.speculate_set:
                    StrSpec = "  ; not directly referenced"
                else:
                    StrSpec = ""

                if cur in self.functions:
                    prefix = "fcn_"
                else:
                    prefix = "loc_"
                print("")
                print(prefix + "{:08x}:".format(cur) + StrSpec)
                nsolved = nsolved + 1
                eob = False
            elif cur in self.non_function_labels:
                if cur in self.jumptab:
                    comment = "  ; may contain a jump table"
                else:
                    comment = ""

                print("\nref_{:08x}:{}".format(cur, comment))
            elif cur in self.endaddrs:
                print("")
                print("endloc_{:08x}:".format(cur))

            if eob:
                if self.str_dict.get(cur) is not None:
                    dbs, dist = self.str_dict[cur]
                    print("db {}".format(dbs))
                    cur += dist
                    continue

                if cur + 3 < endaddr:
                    # check if we should interpret a 32-bit word here
                    usedd = True

                    # there's some known label in the 4 bytes, not a word
                    for addr in [cur + 1, cur + 2, cur + 3]:
                        if addr in self.solved or addr in self.non_function_labels \
                                or addr in self.endaddrs or addr in self.pointers:
                            usedd = False
                            break
                        if self.HasReloc and addr-self.BaseAddr in self.RelocAddr:
                            usedd = False
                            break

                    if usedd:
                        val = self.read32(cur)
                        if not self.HasReloc or cur-self.BaseAddr in self.RelocAddr:
                            if val in self.functions:
                                print("dd fcn_{:08x}".format(val))
                            elif val in self.solved:
                                print("dd loc_{:08x}".format(val))
                            elif val in self.non_function_labels:
                                print("dd ref_{:08x}".format(val))
                            elif val in self.label_adjust:
                                newlab = self.label_adjust[val]
                                print("dd (ref_{:08x} - {})".format(newlab, newlab - val))
                            elif cur % 4 == 0:
                                print("dd 0x{:08x}".format(val))
                            else:
                                usedd = False
                        elif self.HasReloc:
                            if cur % 4 == 0:
                                print("dd 0x{:08x}".format(val))
                            else:
                                usedd = False

                        if usedd:
                            cur = cur + 4
                            continue

                # we don't write 32-bit word, use db
                Byte = self.r2.cmdj("xj 1 @ {}".format(cur))[0]
                print("db 0x{:02x}".format(Byte))
                cur = cur + 1
                continue

            insns = self.get_insns(cur)
            for insn in insns:
                if insn["type"] == "invalid":
                    break

                cur += insn["size"]

                orig_insn = insn["opcode"]
                final_insn, comment = asmfixup(self,insn)

                if insn["type"] not in ["and", "or", "xor"] or insn["refptr"]:
                    # process val and ptr
                    val = insn.get("val")
                    if val is not None:
                        sym_resolv = True
                        if val in self.functions:
                            sym = "fcn_{:08x}".format(val)
                        elif val in self.solved:
                            sym = "loc_{:08x}".format(val)
                        elif val in self.non_function_labels:
                            sym = "ref_{:08x}".format(val)
                        elif val in self.label_adjust:
                            newlab = self.label_adjust[val]
                            sym = "(ref_{:08x} - {})".format(newlab, newlab - val)
                        else:
                            sym_resolv = False

                        if sym_resolv:
                            # we also need to check relocation
                            if not self.HasReloc or self.isRelocInsn(insn["offset"], insn["size"]):
                                comment = orig_insn
                                final_insn = re.sub(
                                    "0x[0-9a-fA-F]*$", sym, final_insn)

                    # since now many instructions don't have "ptr" attribute
                    # we need to match the disasm
                    disasm = final_insn
                    # [... + 0x...]
                    m = re.search("\\+ 0x[0-9a-fA-F]+\\]", disasm)
                    if m is not None:
                        ptr = int(disasm[m.start() + 4:m.end() - 1], 16)
                    else:
                        # [... - 0x...]
                        m = re.search("- 0x[0-9a-fA-F]+\\]", disasm)
                        if m is not None:
                            ptr = int(disasm[m.start() + 4:m.end() - 1], 16)
                            ptr = (1 << 32) - ptr
                        else:
                            # [0x...]
                            m = re.search("0x[0-9a-fA-F]+\\]", disasm)
                            if m is not None:
                                ptr = int(
                                    disasm[m.start() + 2:m.end() - 1], 16)
                            else:
                                ptr = None

                    if ptr is not None:
                        if ptr in self.pe_imports:
                            final_insn = ptrSub(final_insn, self.pe_imports[ptr])
                            comment = orig_insn
                        elif not self.HasReloc or self.isRelocInsn(insn["offset"], insn["size"]):
                            sym_resolv = True
                            if ptr in self.non_function_labels:
                                sym = "ref_{:08x}".format(ptr)
                            elif ptr in self.label_adjust:
                                newlab = self.label_adjust[ptr]
                                sym = "(ref_{:08x} - {})".format(newlab, newlab - ptr)
                            else:
                                sym_resolv = False

                            if sym_resolv:
                                final_insn = ptrSub(final_insn, sym)
                                comment = orig_insn

                if insn["type"] in ["ujmp", "ucall"]:
                    if len(comment) > 0:
                        comment = insn["type"] + ": " + comment
                    else:
                        comment = insn["type"]

                if len(comment) > 0:
                    print(final_insn + "  ; " + comment)
                else:
                    print(final_insn)

                # do not check self.endaddrs before advancing cur, because
                # an end address can also be a start of a basic block
                if cur in self.solved or cur in self.endaddrs:
                    eob = True
                    break

        logging.info("Printed {} locations.".format(nsolved))

        if len(self.solved) != nsolved:
            logging.info("solved {} functions, but there are {} functions to be solved!".format(
                nsolved, len(self.solved)))

    def print_bss(self, addr, endaddr):
        labels = [addr]
        for i in range(addr + 1, endaddr):
            if i in self.non_function_labels:
                labels.append(i)

        labels.append(endaddr)

        for i in range(len(labels) - 1):
            l = labels[i+1] - labels[i]
            print("\nref_{:08x}:".format(labels[i]))
            print("resb", l)

    def run_tool(self, analyze = 'aaaa', header_fmt='org 0x{:08x}'):
        self.init_tool()
        self.find_and_mark_functions(analyze)
        self.analyze_functions()

        if not self.HasReloc:
            for start,end in self.addr_ranges:
                self.analyze_immref(start,end)

        self.analyze_ascii_strings()
        self.scan_labels()
        self.print_assembly(header_fmt)


if __name__ == "__main__":
    r2dumpbin = R2BinaryDumper(scripts=[])
    r2dumpbin.run_tool()
