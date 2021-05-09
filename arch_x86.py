# Copyright (C)  2021 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT

import re

segmem_expr = re.compile('(cs|ds|es|ss|fs|gs):\[(.*)\]')

def asmfixup(dumper, insn):
    orig_insn = insn["opcode"]
    final_insn = orig_insn
    comment = ""

    # correct the r2 assembly to the NASM one
    if insn["type"] == "lea":
        # nasm doesn't like "lea r32, dword ..."
        final_insn = orig_insn.replace("dword ", "")
    elif insn["bytes"] == "f2a5":
        # capstone 4.0.2 gets wrong here
        final_insn = "repne movsd"
    elif ("movsb" in orig_insn or "movsw" in orig_insn or "movsd" in orig_insn \
          or "lods" in orig_insn or "stos" in orig_insn) \
         and "66" in [insn["bytes"][0:2], insn["bytes"][2:4]]:
        # capstone also seems to be wrong here
        comment = orig_insn
        ibytes = dumper.readBytes(insn["offset"], insn["size"])
        final_insn = "db " + ", ".join(["0x{:02x}".format(i) for i in ibytes])
    elif orig_insn[0:4] == "rep ":
        # rep XXXsX
        comment = orig_insn
        final_insn = orig_insn[0:9]
    elif orig_insn[0:5] == "repe ":
        # repe XXXsX
        comment = orig_insn
        final_insn = orig_insn[0:10]
    elif orig_insn[0:6] == "repne ":
        # repne XXXsX
        comment = orig_insn
        final_insn = orig_insn[0:11]
    elif orig_insn[0:6] in ["movsb ","movsw ","movsd ",
                            "stosb ", "stosw ", "stosd ",
                            "lodsb ", "lodsw ", "lodsd ",
                            "cmpsb ", "cmpsw ", "compsd"]:
        comment = orig_insn
        final_insn = orig_insn[0:5]
    elif orig_insn[0:6] == "pushal":
        final_insn = "pushad"
    elif orig_insn[0:5] == "popal":
        final_insn = "popad"
    elif orig_insn[0:12] == "clflush byte":
        # "clflush byte" -> "clflush"
        final_insn = "clflush " + orig_insn[12:]
    elif insn["type"] in ["jmp", "cjmp", "call"]:
        prefix = ""
        if "jecxz" in orig_insn or "loop" in orig_insn:
            pass
        elif insn["type"] != "call":
            if insn["size"] == 2:
                prefix = "short "
            elif insn["size"] >= 5:
                prefix = "near "

        tgt = insn["jump"]
        if tgt in dumper.functions:
            prefix += "fcn_"
        else:
            prefix += "loc_"

        final_insn = re.sub(
            "0x.*", prefix + "{:08x}".format(tgt), orig_insn)
        comment = orig_insn
    elif orig_insn[0:5] in ["fcom ", "fsub ", "fxch ", "fstp ", "fdiv "] or \
         orig_insn[0:6] in ["fmulp ", "fdivp ", "faddp ", "fsubp ", "fdivr "] or \
         orig_insn[0:4] in ["fld "] or \
         orig_insn[0:7] in ["fdivrp "]:
        final_insn = orig_insn.replace("xword", "tword") # 80-bit "ten word"
        final_insn = re.sub("st\(([0-9])\)", "st\\1", final_insn)
        comment = orig_insn
    elif orig_insn[0:7] in ["fnstsw ", "fnsave ", "frstor "]:
        final_insn = orig_insn.replace(" dword", "")
    elif insn["type"] in ["cmp", "add", "sub"] and insn["size"] >= 5 and \
         '[' not in orig_insn:
        val = insn.get("val", 0xffffffff)
        ibytes = dumper.readBytes(insn["offset"], insn["size"])
        if val < 0x80 and ibytes[0] != 0x66:
            # nasm emits short instructions when immediate can fit in one byte
            fixup = True
            if val in dumper.solved or val in dumper.non_function_labels or val in dumper.label_adjust:
                if not dumper.HasReloc or dumper.isRelocInsn(insn["offset"], insn["size"]):
                    fixup = False

            if fixup:
                final_insn = "db " + ", ".join(["0x{:02x}".format(i) for i in ibytes])
                comment = orig_insn

    # fix addressing expressions with a segment selector
    final_insn = segmem_expr.sub('[\\1:\\2]', final_insn)

    if final_insn == orig_insn:
        comment = ""

    return final_insn, comment
