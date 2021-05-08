# Copyright (C)  2021 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT

import os

win32_libpath = '/usr/i686-w64-mingw32/lib/'

def openlib(lib):
    return os.popen('nm --format=bsd ' + win32_libpath + lib)

def search_imports(pipe, functions):
    res = {}
    for L in pipe:
        record = L.split()
        if len(record) != 3 or record[1] != 'I':
            continue

        for imp in functions:
            if '__imp__' + imp + '@' in record[2]:
                res[imp] = record[2]
                break
            elif '__imp__' + imp == record[2]:
                res[imp] = record[2]
                break

    return res

# dllname is the DLL file name without ".dll" extension
def resolv_imports(dllname, functions):
    ar_name = 'lib' + dllname + '.a'
    return search_imports(openlib(ar_name), functions)

"""
r2_pe_import_info: get the following PE import information
- addr_sym_map: address to symbol name mapping
- all_imps: the import name to symbol name mapping (e.g. ExitProcess -> __imp__ExitProcess@4)
- libs: all the dll libraries needed (for linking libs)
"""

def r2_pe_import_info(r2):
    imports = r2.cmdj('iij')
    dll_imp_map = {}
    for i in imports:
        func = i["name"]
        dll = i["libname"].lower()

        if len(dll) > 4 and dll[-4:] == '.dll':
            dll = dll[0:-4] # trim ".dll"
        else:
            print("DLL name {} does not end with .dll.".format(dll))
            continue

        if dll in dll_imp_map:
            dll_imp_map[dll].append(func)
        else:
            dll_imp_map[dll] = [func]

    all_imps = {}
    libs = dll_imp_map.keys()

    for dll in dll_imp_map:
        r = resolv_imports(dll, dll_imp_map[dll])
        all_imps.update(r)

    addr_sym_map = {}
    for i in imports:
        addr_sym_map[i["plt"]] = all_imps[i["name"]]

    return addr_sym_map, all_imps, libs
