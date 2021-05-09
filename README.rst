r2dumpbin - an IA32 binary recovery tool
==========================================

r2dumpbin is a `radare2 <https://radare.org>`__ script to dump a binary to assembly which can be assembled with `NASM <https://nasm.us/>`__.

I wrote this script for working with the `coreboot <https://www.coreboot.org>`__ project to convert `mrc.bin <https://doc.coreboot.org/northbridge/intel/haswell/mrc.bin.html>`__ to assembly, so that I can link it with coreboot romstage, and convert part of assembly code in it to C code, and at last, fully reverse all the code to readable C code.

While recovering the assembly to readable C code is hard work even with `Ghidra <https://ghidra-sre.org/>`__ decompiler released in 2019, I found it easy to do some binary modding or instrumentation after getting an assembly dump. Now I try to use this tool to recover more kinds of binaries besides mrc.bin.

The script is tested in radare2 5.2.1 and python-r2pipe 5.1.0 from Arch Linux.


What does this script do?
---------------------------

The entry point of an mrc.bin is at the beginning of the file, and the binary is loaded at a fixed address (0xfffa0000). Structured binary objects such as PE files have their memory mappings and an entry point.

The script analyzes the code from the entry point, and does the following:

- Find out all the calls, branches and unconditional jumps to find all the executable code in the binary. This can be done by both the script and radare2 `aa` series commands.
- In the non-code areas of the binary, find out all the pointers that points to other places in the binary, so that the result assembly code can be relocatable and linkable.


Usage
------

Install radare2 and Python r2pipe::

  # for Arch use pacman
  pacman -S python-r2pipe
  # if using other distro, you'd better install radare2 from git
  # and install r2pipe with ``pip install --user r2pipe``

r2dumpbin can be used both as a script and a library, the following shows how to use it as a script to dump mrc.bin and Win32 PE files.

Dump mrc.bin
~~~~~~~~~~~~~~~~~~~

Originally I using this tool to dump Haswell mrc.bin to assembly code. The assembly code can be assembled to an object file linkable with coreboot romstage. You can check it out at https://github.com/mytbk/coreboot/tree/haswell-dumpbin (not maintained now).

Load the binary with with radare2, and flag the load virtual address::

  $ r2 mrc.bin 
  [0x00000000]> f va @ 0xfffa0000

At last, use the script to dump mrc.bin to mrc.asm::

  [0x00000000]> . dumpbin.py > mrc.asm

After you get mrc.asm, you can assemble it with nasm, and find the resulting binary identical to the origin mrc.bin::

  nasm mrc.asm # the generated binary is `mrc`
  sha1sum mrc mrc.bin

If you want to link it with other code, you need to:

- remove the `org 0xfffa0000` line
- rename the entry point label, and make it global
- use `-f elf` to generate an ELF object when assembling the code.

Dump Win32 PE files
~~~~~~~~~~~~~~~~~~~~

This tool has initial support for Win32 PE files. It can now dump notepad.exe from wine, and the assembly code can be built to a working notepad. Currently the script only support running under Arch Linux with mingw-w64-crt package installed for Win32 symbol resolution.

An example is located at test/pe::

  $ r2 test/pe/notepad.exe
  [0x00406a20]> . ./dumpbin_pe.py > notepad.asm

And you can assemble notepad.asm and link it to notepad.exe::

  $ nasm -f win32 notepad.asm
  # see the link flag comment in notepad.asm for flags and libs
  $ i686-w64-mingw32-ld -o notepad_new.exe notepad.obj   -e fcn_00406a20 -lkernel32 -ladvapi32 -lcomdlg32 -lgdi32 -lshell32 -lshlwapi -lucrtbase -luser32


Debug
------

To debug this script, you can modify dumpbin.py to change the debug level. Then run r2 like::

  r2 -qc 'f va @ 0xfffa0000; . dumpbin.py > haswell-mrc.asm' haswell-mrc.bin 2>debug.log

A more flexible way is to use r2dumpbin as a library, write your workflow in your script, and debug it.

Bug
---

It is very hard to disassemble an object to correct code. There may be bugs including:

- pointers wrongly recognized or ignored when analyzing non-relocatable objects
- assembly doesn't built to identical code, which needs fix up
