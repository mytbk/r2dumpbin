# Copyright (C)  2018-2020 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT

import re

def hasSubList(heystack, needle):
    L = len(needle)
    idx = 0
    while idx + L <= len(heystack):
        if heystack[idx:idx+L] == needle:
            return True
        idx = idx + 1

    return False


def isAsciiSeq(s):
    for c in s:
        if c in [ord('\t'), ord('\n'), ord('\r')]:
            continue
        if c >= 0x20 and c < 0x7f:
            continue
        return False
    return True


def goodString(s):
    end = len(s) - 1
    if s[end] != 0:
        # if the string is not null terminated, we can still check if it's
        # an ascii string
        return isAsciiSeq(s)

    while end > 0 and s[end] == 0:
        end = end - 1

    if end == 0:
        return False

    return isAsciiSeq(s[0:end])

def toString(s):
    string_segs = []
    seg = ""
    for c in s:
        if c >= 0x20 and c < 0x7f and chr(c) not in ['\'']:
            seg += chr(c)
        else:
            if len(seg) > 0:
                string_segs.append("'" + seg + "'")
                seg = ""

            string_segs.append("0x{:02x}".format(c))

    if len(seg) > 0:
        string_segs.append("'" + seg + "'")

    return ",".join(string_segs)

# get the reloc addresses with:
# readelf -r refcode.elf | cut -d' ' -f1 | grep '^[0-9]' | sed -e 's/^/0x/g' -e 's/$/,/g'
def getReloc(fn):
    f = open(fn, 'r')
    content = f.read()
    f.close()
    return eval('[' + content + ']')

def ptrSub(insn, sym):
    final_insn = insn
    final_insn = re.sub("- 0x[0-9a-fA-F]*\\]", "+ {}]".format(sym), final_insn)
    final_insn = re.sub("\\+ 0x[0-9a-fA-F]*\\]", "+ {}]".format(sym), final_insn)
    final_insn = re.sub("0x[0-9a-fA-F]*\\]", "{}]".format(sym), final_insn)
    return final_insn

def bytes_to_i32(bs):
    return (bs[3] << 24) | (bs[2] << 16) | (bs[1] << 8) | bs[0]
