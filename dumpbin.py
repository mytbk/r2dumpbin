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

import r2pipe
import re

r2 = r2pipe.open()

unsolved = []
solved = set()
endaddrs = set()

FileSize = r2.cmdj("ij")["core"]["size"]
r2.cmd("e asm.bits = 32")

Flags = r2.cmdj("fj")
BaseAddr = 0
for f in Flags:
    if f["name"] == "va":
        BaseAddr = f["offset"]
        r2.cmd("omb. {}".format(BaseAddr))

EndAddr = BaseAddr + FileSize

unsolved.append(BaseAddr)

while len(unsolved) > 0:
    cur = unsolved[0]
    eob = False

    if cur in solved:
        del(unsolved[0])
        continue

    while not eob:
        insns = r2.cmdj("pij @ {}".format(cur))

        for insn in insns:
            if cur >= EndAddr:
                eob = True
                break

            if cur in solved:
                eob = True
                break

            if insn["type"] == "invalid":
                break

            cur += insn["size"]
    
            if insn["type"] == "ret":
                eob = True
                break
            
            if insn["type"] == "jmp":
                unsolved.append(insn["jump"])
                eob = True
                break
    
            if insn["type"] == "cjmp":
                unsolved.append(insn["jump"])
    
            if insn["type"] == "call":
                unsolved.append(insn["jump"])
    
    # try to continue disassembling a possible function
    Bytes = r2.cmdj("xj 3 @ {}".format(cur))
    if Bytes == [0x55, 0x89, 0xe5]: # push ebp; mov ebp, esp
        unsolved.append(cur)
    else:
        endaddrs.add(cur)

    solved.add(unsolved[0])
    del(unsolved[0])

cur = BaseAddr
eob = True

print("bits 32")
print("org 0x{:08x}".format(BaseAddr))

while cur < EndAddr:
    if cur in solved:
        print("")
        print("loc_{:08x}:".format(cur))
        eob = False
    elif cur in endaddrs:
        print("")
        print("loc_{:08x}:".format(cur))

    if eob:
        Byte = r2.cmdj("xj 1 @ {}".format(cur))[0]
        print("db 0x{:02x}".format(Byte))
        cur = cur + 1
        continue

    insns = r2.cmdj("pij @ {}".format(cur))
    for insn in insns:
        if insn["type"] == "invalid":
            break

        cur += insn["size"]

        orig_insn = insn["opcode"]
        if insn["type"] in ["jmp", "cjmp", "call"]:
            if insn["type"] != "call" and insn["size"] == 2:
                prefix = "short "
            else:
                prefix = ""

            lb_insn = re.sub("0x.*", prefix + "loc_{:08x}".format(insn["jump"]), orig_insn)
            print(lb_insn + "  ; " + orig_insn)
        elif orig_insn[0:4] == "rep ":
            # need a work around
            print(orig_insn[0:9] + "  ; " + orig_insn)
        elif insn["type"] == "lea":
            print(orig_insn.replace("dword ", "")) # nasm doesn't like "lea r32, dword ..."
        elif insn["type"] in ["ujmp", "ucall"]:
            print(orig_insn + "  ; " + insn["type"])
        else:
            print(orig_insn)

        # do not check endaddrs before advancing cur, because
        # an end address can also be a start of a basic block
        if cur in solved or cur in endaddrs:
            eob = True
            break
