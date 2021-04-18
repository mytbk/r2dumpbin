from dumpbin import R2BinaryDumper
import r2pipe
from pe_import_resolv import r2_pe_import_info

class TestDumper(R2BinaryDumper):
    def __init__(self, r2 = r2pipe.open()):
        super(TestDumper, self).__init__(r2, scripts = [])

    def init_tool(self, addr_ranges, code_ranges):
        self.BaseAddr = 0
        self.FileSize = self.r2.cmdj("ij")["core"]["size"]

        Flags = self.r2.cmdj("fj")
        for f in Flags:
            if "fcn" in f["name"]:
                # support manually marked functions
                fcn = f["offset"]
                self.unsolved.append(fcn)
                self.functions.add(fcn)

        self.addr_ranges = addr_ranges
        self.code_ranges = code_ranges

        entries = self.r2.cmdj("iej")
        self.entries = [e["vaddr"] for e in entries]
        self.unsolved += self.entries

        self.pe_imports, _, self.pe_libs = r2_pe_import_info(self.r2)

    def print_assembly(self):
        print(";; Generated with r2dumpbin (https://github.com/mytbk/r2dumpbin)\n")
        print("bits 32")
        for sym in self.pe_imports.values():
            print("extern {}".format(sym))

        print("; link flag and libs: " + '-e fcn_{:08x} '.format(self.entries[0]) +
              ' '.join(['-l' + l for l in self.pe_libs]))

        for addr,_ in self.addr_ranges:
            self.print_range(addr)

    def run_tool(self):
        self.init_tool(addr_ranges = [(0x401000,0x45c000)], code_ranges = [(0x401000,0x407000)])
        self.find_and_mark_functions('aa')
        self.analyze_functions()
        for r in self.addr_ranges:
            start, end = r
            self.analyze_immref(start)

        self.analyze_ascii_strings()
        self.scan_labels()
        self.print_assembly()

if __name__ == "__main__":
    r2dumpbin = TestDumper()
    r2dumpbin.run_tool()
