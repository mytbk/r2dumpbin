import re

def asmfixup(dumper, insn):
    orig_insn = insn["opcode"]
    final_insn = orig_insn
    comment = ""

    # correct the r2 assembly to the NASM one
    if insn["type"] == "lea":
        # nasm doesn't like "lea r32, dword ..."
        final_insn = orig_insn.replace("dword ", "")
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
    elif orig_insn[0:6] in ["movsb ","movsw ","movsd "]:
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
        if "jecxz" in orig_insn:
            pass
        elif insn["type"] != "call":
            if insn["size"] == 2:
                prefix = "short "
            elif insn["size"] == 5:
                prefix = "near "

        tgt = insn["jump"]
        if tgt in dumper.functions:
            prefix += "fcn_"
        else:
            prefix += "loc_"

        final_insn = re.sub(
            "0x.*", prefix + "{:08x}".format(tgt), orig_insn)
        comment = orig_insn
    elif orig_insn[0:5] in ["fcom ", "fsub ", "fxch ", "fstp "] or \
         orig_insn[0:6] in ["fmulp ", "fdivp ", "faddp ", "fsubp "] or \
         orig_insn[0:4] in ["fld "]:
        final_insn = orig_insn.replace("xword", "tword") # 80-bit "ten word"
        final_insn = re.sub("st\(([0-9])\)", "st\\1", final_insn)
        comment = orig_insn

    if final_insn == orig_insn:
        comment = ""

    return final_insn, comment
