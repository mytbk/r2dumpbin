# Copyright (C)  2021 Iru Cai <mytbk920423@gmail.com>
# SPDX-License-Identifier: MIT

import sys

from pe_import_resolv import r2_pe_import_info
import r2pipe

def print_imp(filename=None):
    if filename is None:
        p = r2pipe.open()
    else:
        p = r2pipe.open(filename)

    return r2_pe_import_info(p)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        addr_sym_map, imp, libs = print_imp(sys.argv[1])
    else:
        addr_sym_map, imp, libs = print_imp(None)

    print(addr_sym_map)
    print(imp)
    print(list(imp.values()))
    print(libs)
