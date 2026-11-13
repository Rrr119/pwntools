Test PE images used by the ROP/PE tests.

test-x86:
    PE32, preferred base 0x00400000.  Contains pop eax/ebx/ecx/edx; ret,
    stack adjustment gadgets and import thunks for MessageBoxA and
    ExitProcess.  Includes a base relocation block.

test-x64:
    PE32+, preferred base 0x140000000.  Contains pop rcx/rdx/r8/r9; ret,
    stack adjustment gadgets and import thunks for MessageBoxA and
    ExitProcess.

The import tables are intentionally small hand-written tables so that the
fixtures can be checked into the source tree without a Windows toolchain.
