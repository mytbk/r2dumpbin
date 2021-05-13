#!/usr/bin/env python

import re
import sys

'''
an example to instrument memory accesses in the assembly code
'''

load_pattern = re.compile('(mov[a-z]*) ([a-z]+),.*\[(.*)\]')
store_pattern = re.compile('(mov[a-z]*) .*\[(.*)\],[ \t]*([0-9a-z]+)')
comment = re.compile(';.*')

extmap = { 'mov': '', 'movsx': 'sext', 'movzx': 'zext' }
sizemap = { 'byte': '8', 'word': '16', 'dword': '32' }
pushad_offsets = {
        'edi': 0, 'di': 0, 'dl': 0,
        'esi': 4, 'si': 4, 'sil': 4,
        'ebp': 8, 'bp': 8,
        'ebx': 16, 'bx': 16, 'bl': 16, 'bh': 17,
        'edx': 20, 'dx': 20, 'dl': 20, 'dh': 21,
        'ecx': 24, 'cx': 24, 'cl': 24, 'ch': 25,
        'eax': 28, 'ax': 28, 'al': 28, 'ah': 29,
        }
ax = { '8': 'al', '16': 'ax', '32': 'eax' }
extreg = {
        'al': 'eax', 'ax': 'eax', 'bl': 'ebx', 'bx': 'eax',
        'cl': 'ecx', 'cx': 'ecx', 'dl': 'edx', 'dx': 'edx',
        'si': 'esi', 'di': 'edi', 'sp': 'esp', 'bp': 'ebp'
        }

def header():
    header_str = ''
    for op in ['read', 'write']:
        for sz in sizemap.values():
            for ext in extmap.values():
                header_str += ('extern ' + op + sz + ext + '\n')

    return header_str

def emitLoad(insn, movtype, dst, ea):
    load_template = r'''pushad
lea eax, [{EA}]
push eax
call {readfunc}
add esp, 4
mov {dsttype} [esp+{reg_off}], {AX}
popad
    '''
    # for mov, just call readXX
    # for mov[sz]x, call readXX[sz]ext, and make type to dword
    ext_type = extmap.get(movtype, '')
    size_type = ''
    for sz in sizemap.keys():
        if sz in insn:
            size_type = sz
            dsttype = sz
            axreg = ax[sizemap[sz]]

    if movtype in ['movsx', 'movzx']:
        dsttype = 'dword'
        axreg = 'eax'

    print('; LOAD: ' + insn)
    print(load_template.format(EA=ea, dsttype=dsttype,
        readfunc='read'+sizemap[size_type]+ext_type,
        reg_off=pushad_offsets[dst], AX = axreg))

def emitStore(insn, movtype, ea, val):
    store_template = r'''pushad
push {val}
lea eax, [{EA}]
push eax
call {writefunc}
add esp, 8
popad
    '''
    size_type = ''
    for sz in sizemap.keys():
        if sz in insn:
            size_type = sz
            dsttype = sz

    # FIXME: what about ah...
    val_ = extreg.get(val)
    if val_ is not None:
        val = val_

    print('; STORE: ' + insn)
    print(store_template.format(EA=ea, val=val,
        writefunc='write'+sizemap[size_type]))

def instrument_memory(lines):
    for L in lines:
        # remove comment
        L = L.strip('\r\n')
        insn = comment.sub('', L).strip()

        # try to match patterns
        matched = False
        m = load_pattern.fullmatch(insn)
        if m is not None:
            movtype, reg, ea = m.groups()
            emitLoad(insn, movtype, reg, ea)
            matched = True
        
        m = store_pattern.fullmatch(insn)
        if m is not None:
            movtype, ea, val = m.groups()
            emitStore(insn, movtype, ea, val)
            matched = True

        if not matched:
            print(L)

if __name__ == '__main__':
    print(header())
    instrument_memory(open(sys.argv[1], 'r'))
