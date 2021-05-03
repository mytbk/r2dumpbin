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
    result = ""
    started = False
    for i in range(len(s)):
        c = s[i]
        if started:
            result += ","
        if c >= 0x20 and c < 0x7f and chr(c) not in ['\'', '%', ',']:
            result += "'" + chr(c) + "'"
        elif chr(c) == '%':
            # FIXME: does nasm accept "%1", "%2",...?
            #        Leave the handling code here...
            result += "'" + chr(c) + "'"
        else:
            result += "0x{:02x}".format(c)
        started = True
    return result.replace("','", "")


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
