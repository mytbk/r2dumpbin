r2dumpbin - dump mrc.bin to assembly
==========================================

r2dumpbin is a `radare2 <https://radare.org>`__ script to dump a binary to assembly which can be assembled with NASM.

I wrote this script for working with the `coreboot <https://www.coreboot.org>`__ project to convert mrc.bin to assembly, so that I can link it with coreboot romstage, and convert some assembly code in it to C code, and at last, fully reverse all the code to readable C code.


What does this script do?
---------------------------

The entry point of mrc.bin is at the beginning of the file, and is loaded at an fixed address (in coreboot it's 0xfffa0000). The script analyzes the code from the beginning, and does the following:

- find out all the calls, branches and unconditional jumps to find all the executable code in the binary
- in the non-code areas of the binary, find out all the pointers that points to other places in the binary


Usage
------

Install radare2 and Python r2pipe::

  # for Arch use pacman
  # if using other distro, you'd better install it from git
  pacman -S radare2
  pip install --user r2pipe

Load the binary with with radare2, and flag the load virtual address::

  $ r2 mrc.bin 
  [0x00000000]> f va @ 0xfffa0000

At last, use the script to dump mrc.bin to mrc.asm::

  [0x00000000]> . dumpbin.py > mrc.asm

After you get mrc.asm, you can assemble it with nasm, and find the resulting binary identical to the origin mrc.bin::

  nasm mrc.asm # the generated binary is `mrc`
  sha1sum mrc mrc.bin

If you want to link it with other code, you need to remove the `org 0xfffa0000` line, rename the entry point label, and make it global. And use `-f elf` to generate an ELF object when assemble the code.

Bug
---

Some array data reference is not analyzed correctly, for example, the C code `array[idx - 1]` is compiled as `(array - 1)[idx]` in machine code, so dumpbin can generate some incorrect data sections as following::

  ref_fffcc218:
  dd loc_fffc6340
  dd loc_fffc63f4
  dd loc_fffc6298
  dd loc_fffc63f4
  dd loc_fffc6283
  dd loc_fffc63f4
  dd loc_fffc6365
  dd loc_fffc6354
  dd loc_fffc6283
  db 0xa7
  db 0x63
  db 0xfc
  
  ref_fffcc23f:
  db 0xff
  db 0x0e
  
Actually, the last element of ref_fffcc218 is fcn_fffc63a7, but because of there's `(ref_fffcc240 - 1)[idx]` in the code, ref_fffcc23f breaks the last function pointer apart.

Fortunately, I only found this error in the dumped out code, and no error was observed before I found this incorrect data reference because the running code didn't use fcn_fffc63a7.
