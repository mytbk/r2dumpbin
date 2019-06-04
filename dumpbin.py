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

import r2pipe
import re
import logging

logging.basicConfig(level=logging.INFO)

Aggresive = 2

def get_insns(r2, addr):
    return r2.cmdj("pij 10 @ {}".format(addr))


def hasSubList(heystack, needle):
    L = len(needle)
    idx = 0
    while idx + L <= len(heystack):
        if heystack[idx:idx+L] == needle:
            return True
        idx = idx + 1

    return False


def goodString(s):
    end = len(s) - 1
    if s[end] != 0:
        return False
    while s[end] == 0:
        end = end - 1
    for c in s[0:end]:
        if c in [ord('\t'), ord('\n'), ord('\r')]:
            continue
        if c >= 0x20 and c < 0x7f:
            continue
        return False
    return True


def toString(s):
    result = ""
    started = False
    for c in s:
        if started:
            result += ","
        if c >= 0x20 and c < 0x7f and c != '\'':
            result += "'" + chr(c) + "'"
        else:
            result += "0x{:02x}".format(c)
        started = True
    return result.replace("','", "")


r2 = r2pipe.open()

unsolved = []
speculate = set()
speculate_set = set()
solved = set()
endaddrs = set()
immref = set()
functions = set()

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

SpecMode = False

while len(unsolved) > 0 or len(speculate) > 0:
    if len(unsolved) == 0:
        unsolved = list(speculate.difference(solved))
        speculate.clear()
        SpecMode = True
        if len(unsolved) == 0:
            break
        logging.debug("Analyze undirect functions.")

    cur = unsolved[0]
    eob = False

    if cur in solved:
        del(unsolved[0])
        continue

    if SpecMode:
        speculate_set.add(cur)

    logging.debug("Analyzing {:08x}".format(cur))

    while not eob:
        insns = get_insns(r2, cur)

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

            if insn.get("val") is not None and insn["val"] >= BaseAddr and insn["val"] < EndAddr:
                immref.add(insn["val"])

            ptr = insn.get("ptr")
            if ptr is not None:
                if ptr < 0:
                    ptr += (1 << 32)
                elif ptr >= (1 << 32): # new radare2 seems to be using ut64
                    ptr &= 0xffffffff

                if ptr >= BaseAddr and ptr < EndAddr:
                    immref.add(ptr)

            if insn["type"] == "ret":
                eob = True
                break
            
            if insn["type"] == "jmp":
                unsolved.append(insn["jump"])
                eob = True
                break

            if insn["type"] == "ujmp":
                if ptr is not None and ptr in immref and ptr % 4 == 0:
                    cur_ptr = ptr
                    while True:
                        Bytes = r2.cmdj("xj 4 @ {}".format(cur_ptr))
                        loc = (Bytes[3] << 24) | (Bytes[2] << 16) | (Bytes[1] << 8) | Bytes[0]
                        if loc >= BaseAddr and loc < EndAddr:
                            unsolved.append(loc)
                            cur_ptr += 4
                        else:
                            break
                eob = True
                break

            if insn["type"] == "cjmp":
                unsolved.append(insn["jump"])
    
            if insn["type"] == "call":
                unsolved.append(insn["jump"])
                functions.add(insn["jump"])
    
    endaddrs.add(cur)

    # try to continue disassembling a possible function
    # search to a 4-byte boundary
    while True:
        Bytes = r2.cmdj("xj 256 @ {}".format(cur))
        if Bytes[0:3] == [0x55, 0x89, 0xe5]: # push ebp; mov ebp, esp
            speculate.add(cur)
            functions.add(cur)
            break
        elif Aggresive >= 1 and Bytes[0] == 0x55 and hasSubList(Bytes[1:10], [0x89, 0xe5]):
            # push ebp; ... ; mov ebp, esp
            speculate.add(cur)
            functions.add(cur)
            break
        elif Aggresive >= 2 and Bytes[0] == 0x55 and hasSubList(Bytes[1:20], [0x89, 0xe5]):
            # push ebp; ... ; mov ebp, esp
            speculate.add(cur)
            functions.add(cur)
            break
        elif Aggresive >= 9 and Bytes[0] == 0x55: # just a push ebp
            speculate.add(cur)
            functions.add(cur)
            break

        if cur % 4 == 0:
            break
        else:
            cur += 1

    solved.add(unsolved[0])
    del(unsolved[0])

logging.info("Analyze complete, going to output ASM.")
logging.info("{} locations to be printed.".format(len(solved)))

non_function_immref = immref.difference(solved)

logging.info("Analyze data references.")
cur = BaseAddr
eob = True
while cur < EndAddr:
    if cur in solved:
        eob = False

    if eob:
        if cur % 4 == 0 and cur + 4 <= EndAddr:
            usedd = True
            for addr in [cur + 1, cur + 2, cur + 3]:
                if addr in solved or addr in non_function_immref or addr in endaddrs:
                    usedd = False
                    break
            if usedd:
                Bytes = r2.cmdj("xj 4 @ {}".format(cur))
                val = (Bytes[3] << 24) | (Bytes[2] << 16) | (Bytes[1] << 8) | Bytes[0]
                if val >= BaseAddr and val < EndAddr and not val in solved:
                    non_function_immref.add(val)

                cur = cur + 4
                continue

        # cur is not 4B aligned or not usedd
        cur = cur + 1
        continue

    else: # not eob
        insns = get_insns(r2, cur)
        for insn in insns:
            if insn["type"] == "invalid":
                break

            cur += insn["size"]
            if cur in solved or cur in endaddrs:
                eob = True
                break


logging.info("{} non function immediate references.".format(len(non_function_immref)))

logging.info("Searching for ASCII strings.")

ref_list = list(non_function_immref)
ref_list.sort()
ref_list.append(EndAddr)

str_dict = dict()

for idx in range(0, len(ref_list) - 1):
    addr = ref_list[idx]
    dist = ref_list[idx + 1] - addr
    if dist < 4 or dist > 100:
        continue

    Bytes = r2.cmdj("xj {} @ {}".format(dist, addr))
    if goodString(Bytes):
        str_dict[addr] = (toString(Bytes), dist)

logging.info("{} ASCII strings found.".format(len(str_dict)))

cur = BaseAddr
eob = True
nsolved = 0

print(";; Generated with r2dumpbin (https://github.com/mytbk/r2dumpbin)\n")
print("bits 32")
print("org 0x{:08x}".format(BaseAddr))

while cur < EndAddr:
    if cur in solved:
        if cur in speculate_set:
            StrSpec = "  ; not directly referenced"
        else:
            StrSpec = ""

        if cur in functions:
            prefix = "fcn_"
        else:
            prefix = "loc_"
        print("")
        print(prefix + "{:08x}:".format(cur) + StrSpec)
        nsolved = nsolved + 1
        eob = False
    elif cur in non_function_immref:
        print("")
        print("ref_{:08x}:".format(cur))
    elif cur in endaddrs:
        print("")
        print("loc_{:08x}:".format(cur))

    if eob:
        if str_dict.get(cur) is not None:
            dbs, dist = str_dict[cur]
            print("db {}".format(dbs))
            cur += dist
            continue

        if cur % 4 == 0 and cur + 4 <= EndAddr:
            usedd = True
            for addr in [cur + 1, cur + 2, cur + 3]:
                if addr in solved or addr in non_function_immref or addr in endaddrs:
                    usedd = False
                    break
            if usedd:
                Bytes = r2.cmdj("xj 4 @ {}".format(cur))
                val = (Bytes[3] << 24) | (Bytes[2] << 16) | (Bytes[1] << 8) | Bytes[0]
                if val in functions:
                    print("dd fcn_{:08x}".format(val))
                elif val in solved:
                    print("dd loc_{:08x}".format(val))
                elif val in non_function_immref:
                    print("dd ref_{:08x}".format(val))
                else:
                    print("dd 0x{:08x}".format(val))
                cur = cur + 4
                continue

        Byte = r2.cmdj("xj 1 @ {}".format(cur))[0]
        print("db 0x{:02x}".format(Byte))
        cur = cur + 1
        continue

    insns = get_insns(r2, cur)
    for insn in insns:
        if insn["type"] == "invalid":
            break

        cur += insn["size"]

        orig_insn = insn["opcode"]
        final_insn = orig_insn
        comment = ""

        # First, correct the r2 assembly to the NASM one
        if insn["type"] == "lea":
            # nasm doesn't like "lea r32, dword ..."
            final_insn = orig_insn.replace("dword ", "")
        elif orig_insn[0:4] == "rep ":
            comment = orig_insn
            final_insn = orig_insn[0:9]
        elif insn["type"] in ["jmp", "cjmp", "call"]:
            prefix = ""
            if insn["type"] != "call":
                if insn["size"] == 2:
                    prefix = "short "
                elif insn["size"] == 5:
                    prefix = "near "

            tgt = insn["jump"]
            if tgt in functions:
                prefix += "fcn_"
            else:
                prefix += "loc_"
            final_insn = re.sub("0x.*", prefix + "{:08x}".format(tgt), orig_insn)
            comment = orig_insn

        # process val and ptr
        val = insn.get("val")
        if val is not None:
            if val in functions:
                prefix = "fcn_"
            elif val in solved:
                prefix = "loc_"
            elif val in non_function_immref:
                prefix = "ref_"
            else:
                prefix = ""

            if len(prefix) > 0:
                comment = orig_insn
                final_insn = re.sub("0x[0-9a-fA-F]*$", prefix + "{:08x}".format(val), final_insn)

        ptr = insn.get("ptr")
        # note that radare2 set ptr as val for mov instructions
        # when memory displacement is small and immediate is big
        if ptr is not None and ptr != val:
            if ptr < 0:
                ptr += (1 << 32)
            elif ptr >= (1 << 32):
                ptr &= 0xffffffff

            if ptr in non_function_immref:
                final_insn = re.sub("- 0x[0-9a-fA-F]*\\]", "+ ref_{:08x}]".format(ptr), final_insn)
                final_insn = re.sub("\\+ 0x[0-9a-fA-F]*\\]", "+ ref_{:08x}]".format(ptr), final_insn)
                final_insn = re.sub("0x[0-9a-fA-F]*\\]", "ref_{:08x}]".format(ptr), final_insn)
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

        # do not check endaddrs before advancing cur, because
        # an end address can also be a start of a basic block
        if cur in solved or cur in endaddrs:
            eob = True
            break

logging.info("Printed {} locations.".format(nsolved))

if len(solved) != nsolved:
    logging.info("solved {} functions, but there are {} functions to be solved!".format(nsolved, len(solved)))
