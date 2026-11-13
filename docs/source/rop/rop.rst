.. testsetup:: *

   import time
   from glob import glob

   from pwnlib.asm import asm
   from pwnlib import constants
   from pwnlib.context import context
   from pwnlib.elf import ELF
   from pwnlib.pe import PE
   from pwnlib.rop import ROP
   from pwnlib.rop.call import Call, AppendedArgument
   from pwnlib.elf.maps import CAT_PROC_MAPS_EXIT
   from pwnlib.util.packing import *
   from pwnlib.util.fiddling import *
   from pwnlib.tubes.process import process
   from pwnlib import shellcraft
   from pwnlib.util.misc import which
   import pwnlib.data

   context.clear()

   # TODO: Remove global LINUX flag
   import doctest
   doctest_additional_flags = doctest.OPTIONFLAGS_BY_NAME['LINUX']


Windows ROP with PE files
-------------------------

``ROP`` accepts :class:`pwnlib.pe.PE` objects as well as paths or byte strings
whose first bytes are the PE ``MZ`` signature.  The PE reader exposes the
section table, exports, imports, import thunks and base relocations.  Set
``context.binary`` to a ``PE`` object to inherit ``amd64``/``i386``, 64/32-bit
and ``os='windows'`` automatically::

    context.clear()
    pe = context.binary = PE('./target.exe')
    rop = ROP(pe)
    rop.call('VirtualAlloc', [0, 0x1000, 0x3000, 0x40])

Addresses are virtual addresses, not file offsets.  ``PE.load_addr`` is the
preferred image base stored in the optional header, while ``PE.address`` is
the base where the image is actually loaded.  If ASLR or a debugger placed the
image at a different address, assign the runtime base before building the
chain::

    pe.address = 0x7ff600000000
    rop = ROP(pe)

This updates exported symbols, imported function addresses and relocation
addresses.  Gadget addresses found by ROPgadget are converted from PE RVAs
using the same runtime base, so they can be checked one by one in WinDbg or
x64dbg.

For imports, there are two different useful addresses.  ``PE.imports[name]``
(also available as ``PE.iat[name]``) is the IAT slot holding the final library
pointer.  ``PE.thunks[name]`` is the executable ``jmp [IAT]`` or
``call [IAT]`` thunk found in an executable section.  :meth:`ROP.call` uses
the thunk, because returning to an IAT slot would execute data rather than
code.  If a packed binary has no recognizable thunk, the name is intentionally
absent from ``PE.symbols``; use a chain-specific call target or resolve the
thunk manually.  Qualified names such as ``kernel32.dll!VirtualAlloc`` are
also accepted.

On x64, Windows passes the first four arguments in ``rcx``, ``rdx``, ``r8``
and ``r9``.  The caller must also reserve the 32-byte shadow space between the
return address and the fifth argument.  ``ROP.call`` emits this layout and
uses an ``add rsp, N; ret`` gadget when execution must continue after the
callee returns.  When ``base=`` (the runtime stack address of the chain) is
known, it also inserts a single ``ret`` if needed so that RSP is 16-byte
aligned before a Win64 call.  For example, a call with six arguments is
laid out as::

    pop r9; ret        <- argument 3
    4
    pop r8; ret        <- argument 2
    3
    pop rdx; ret       <- argument 1
    2
    pop rcx; ret       <- argument 0
    1
    import thunk       <- function entry
    add rsp, 0x38; ret <- return address and stack cleanup
    shadow space       <- four qwords
    argument 4
    argument 5

On x86, all arguments are placed on the stack.  Imported Windows API functions
use the stdcall convention by default, so the callee removes its arguments
with ``ret N``.  The ROP builder therefore puts a plain ``ret`` gadget in the
return-address slot; after the callee cleans its stack, that gadget continues
at the next chain entry.  Other x86 targets default to cdecl.  Either choice
can be overridden by passing ``abi=pwnlib.abi.windows_i386`` or
``abi=pwnlib.abi.windows_i386_cdecl``.

Relocation data is available through ``PE.relocations`` as
:class:`pwnlib.pe.PERelocation` objects with ``address``, ``rva``, ``type``
and ``kind`` attributes.  ASLR is reported through ``PE.aslr``; DEP through
``PE.dep``.  These are inspection helpers, not a substitute for knowing the
runtime module base.

The checked-in test image can be used to verify the address and argument
layout directly:

.. doctest::

    >>> pe = PE(pwnlib.data.pe.get('test-x64'))
    >>> rop = ROP(pe)
    >>> hex(rop.rcx.address)
    '0x140001000'
    >>> rop.call('MessageBoxA', [1, 2, 3, 4])
    >>> hex(int.from_bytes(rop.chain()[0x40:0x48], 'little'))
    '0x14000101a'
    >>> hex(pe.thunks['MessageBoxA'])
    '0x14000101a'


:mod:`pwnlib.rop.rop` --- Return Oriented Programming
==========================================================

.. automodule:: pwnlib.rop.rop
   :members:
