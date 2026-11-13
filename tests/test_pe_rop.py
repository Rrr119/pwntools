import struct

import pytest

from pwnlib.context import context
from pwnlib.data.pe import get as get_pe
from pwnlib.pe import PE
from pwnlib.rop import ROP


@pytest.fixture(autouse=True)
def clear_context():
    context.clear()
    yield
    context.clear()


def words(data, word_size):
    return [
        int.from_bytes(data[offset:offset + word_size], 'little')
        for offset in range(0, len(data), word_size)
    ]


def test_pe_parses_sections_imports_thunks_and_relocations():
    pe = PE(get_pe('test-x86'))

    assert pe.arch == 'i386'
    assert pe.bits == 32
    assert pe.os == 'windows'
    assert pe.address == 0x400000
    assert pe.entry == 0x401000
    assert pe.get_section_by_name('.text').address == 0x401000
    assert pe.read(0x401000, 2) == b'\x58\xc3'

    assert pe.iat['MessageBoxA'] == 0x40204c
    assert pe.thunks['MessageBoxA'] == 0x401015
    assert pe.symbols['MessageBoxA'] == 0x401015
    assert pe.symbols['kernel32.dll!ExitProcess'] == 0x40101b

    assert [(reloc.address, reloc.kind) for reloc in pe.relocations] == [
        (0x401017, 'HIGHLOW'),
        (0x40101d, 'HIGHLOW'),
    ]

    pe.address = 0x500000
    assert pe.symbols['MessageBoxA'] == 0x501015
    assert pe.imports['MessageBoxA'] == 0x50204c


def test_pe64_gadget_addresses_and_win64_call_chain():
    path = get_pe('test-x64')
    pe = PE(path)
    rop = ROP(path)

    assert (rop.arch, rop.bits, rop.os) == ('amd64', 64, 'windows')
    assert rop.ret.address == 0x140001001
    assert rop.rcx.address == 0x140001000
    assert rop.rdx.address == 0x140001002
    assert rop.r8.address == 0x140001004
    assert rop.r9.address == 0x140001007
    assert rop.search(move=0x38).address == 0x14000100f

    rop.call('MessageBoxA', [1, 2, 3, 4, 5, 6])
    rop.call('ExitProcess', [0])
    chain = words(rop.chain(), 8)

    assert chain[0:9] == [
        0x140001007,  # pop r9; ret
        4,
        0x140001004,  # pop r8; ret
        3,
        0x140001002,  # pop rdx; ret
        2,
        0x140001000,  # pop rcx; ret
        1,
        0x14000101a,  # MessageBoxA import thunk
    ]
    assert chain[9] == 0x14000100f  # add rsp, 0x38; ret
    assert chain[14:16] == [5, 6]
    assert chain[17:20] == [
        0x140001000,   # return address for ExitProcess setup
        0,
        0x140001020,   # ExitProcess import thunk
    ]


def test_pe32_gadget_addresses_and_stdcall_chain():
    pe = PE(get_pe('test-x86'))
    rop = ROP(pe)

    assert rop.eax.address == 0x401000
    assert rop.ebx.address == 0x401002
    assert rop.ecx.address == 0x401004
    assert rop.edx.address == 0x401006
    assert rop.ret.address == 0x401001

    rop.call('MessageBoxA', [1, 2, 3, 4])
    rop.call('ExitProcess', [0])
    chain = words(rop.chain(), 4)

    assert chain[:9] == [
        0x401015,
        0x401001,
        1,
        2,
        3,
        4,
        0x40101b,
        chain[7],
        0,
    ]


def test_pe_can_be_loaded_from_bytes_and_uses_windows_abi():
    path = get_pe('test-x64')
    blob = open(path, 'rb').read()

    pe = PE(blob)
    rop = ROP(pe)
    rop.call('MessageBoxA', [1, 2, 3, 4])

    call = next(slot for slot in rop._chain if hasattr(slot, 'abi'))
    assert call.abi.register_arguments == ['rcx', 'rdx', 'r8', 'r9']
    assert call.abi.stack_minimum == 32

    rop = ROP(blob)
    assert rop.rcx.address == 0x140001000

    rop = ROP.from_blob(blob)
    assert rop.rcx.address == 0x140001000


def test_context_binary_accepts_pe():
    pe = context.binary = PE(get_pe('test-x64'))
    assert isinstance(pe, PE)
    assert (context.arch, context.bits, context.os) == ('amd64', 64, 'windows')

    context.clear()
    context.binary = get_pe('test-x86')
    assert isinstance(context.binary, PE)
    assert (context.arch, context.bits, context.os) == ('i386', 32, 'windows')


def test_win64_call_aligns_known_stack_base():
    pe = PE(get_pe('test-x64'))
    rop = ROP(pe, base=0x1008)
    rop.call('ExitProcess', [0])
    chain = words(rop.chain(), 8)

    assert chain[:4] == [0x140001000, 0, 0x140001001, 0x140001020]
