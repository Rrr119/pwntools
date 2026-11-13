r"""
Exposes functionality for manipulating Portable Executable (PE) files.

The parser is intentionally small and focuses on the information needed by
:class:`pwnlib.rop.rop.ROP`: sections, exports, imports, import thunks and
base relocations.  It is backed by :mod:`pefile`, which also handles the
many malformed-but-loadable executables found in the wild.

Example:

    >>> context.clear(arch='amd64', os='windows')
    >>> from pwnlib.data.pe import get
    >>> pe = PE(get('test-x64'))
    >>> pe.arch, pe.bits, hex(pe.entry)
    ('amd64', 64, '0x140001000')
    >>> hex(pe.iat['MessageBoxA']), hex(pe.thunks['MessageBoxA'])
    ('0x140002060', '0x14000101a')
"""

import os
import tempfile
import types

import pefile

from pwnlib.asm import disasm
from pwnlib.context import context
from pwnlib.util import packing

__all__ = ['PE', 'PERelocation', 'PESection']

IMAGE_FILE_DLL = 0x2000

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

_RELOCATION_TYPES = {
    0: 'ABSOLUTE',
    1: 'HIGH',
    2: 'LOW',
    3: 'HIGHLOW',
    4: 'HIGHADJ',
    5: 'MIPS_JMPADDR',
    9: 'MIPS_JMPADDR16',
    10: 'DIR64',
}


def _name(value):
    if isinstance(value, bytes):
        return packing._decode(value)
    return value


class PESection:
    """
    A section in a :class:`PE` file.

    Addresses are virtual addresses in the currently selected image base
    (``pe.address``), while the raw offsets describe the on-disk section.
    """

    def __init__(self, pe, section):
        self.pe = pe
        self._section = section
        self.name = _name(section.Name.rstrip(b'\x00'))
        self.virtual_size = section.Misc_VirtualSize
        self.raw_size = section.SizeOfRawData
        self.raw_offset = section.PointerToRawData
        self.characteristics = section.Characteristics
        self.header = types.SimpleNamespace(
            sh_addr=self.pe.load_addr + section.VirtualAddress,
            sh_size=section.Misc_VirtualSize,
            sh_offset=section.PointerToRawData,
            sh_flags=section.Characteristics,
        )

    @property
    def rva(self):
        return self._section.VirtualAddress

    @property
    def address(self):
        return self.pe.address + self.rva

    @property
    def virtual_address(self):
        return self.address

    @property
    def size(self):
        return self.virtual_size

    @property
    def readable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_READ)

    @property
    def writable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    @property
    def executable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def data(self):
        return self._section.get_data()

    def get_data(self):
        return self.data

    def __repr__(self):
        return '%s(name=%r, address=%#x, size=%#x)' % (
            self.__class__.__name__,
            self.name,
            self.address,
            self.size,
        )


class PERelocation:
    """
    A single PE base relocation.

    ``address`` is the virtual address of the relocated field, and ``type``
    is the raw ``IMAGE_REL_BASED_*`` value.
    """

    def __init__(self, pe, rva, reloc_type):
        self.pe = pe
        self.rva = rva
        self.type = reloc_type

    @property
    def address(self):
        return self.pe.address + self.rva

    @property
    def kind(self):
        return _RELOCATION_TYPES.get(self.type, 'UNKNOWN')

    def __iter__(self):
        return iter((self.address, self.type))

    def __eq__(self, other):
        if isinstance(other, PERelocation):
            return self.address == other.address and self.type == other.type
        return tuple(self) == other

    def __repr__(self):
        return '%s(address=%#x, type=%s)' % (
            self.__class__.__name__,
            self.address,
            self.kind,
        )


class PE:
    """Encapsulates information about a PE file."""

    bits = 32
    bytes = 4
    endian = 'little'
    os = 'windows'
    arch = 'i386'

    def __init__(self, path_or_bytes, checksec=False):
        self._tempfile = None

        if isinstance(path_or_bytes, (bytes, bytearray)):
            if not path_or_bytes.startswith(b'MZ'):
                raise ValueError('PE data must start with the MZ magic')
            temp = tempfile.NamedTemporaryFile(
                prefix='pwnlib-pe-', suffix='.exe', delete=False
            )
            temp.write(path_or_bytes)
            temp.close()
            self._tempfile = temp.name
            path = temp.name
        else:
            path = path_or_bytes

        self.pe = pefile.PE(path)
        self.path = packing._need_text(os.path.abspath(path))
        with open(path, 'rb') as fd:
            self.data = fd.read()

        optional = self.pe.OPTIONAL_HEADER
        self.bits = 64 if optional.Magic == 0x20b else 32
        self.bytes = self.bits // 8
        self.arch = {
            0x14c: 'i386',
            0x8664: 'amd64',
        }.get(self.pe.FILE_HEADER.Machine)
        if self.arch is None:
            raise ValueError('Unsupported PE machine type %#x' % self.pe.FILE_HEADER.Machine)

        self.endian = 'little'
        self.os = 'windows'
        self.load_addr = optional.ImageBase
        self._address = self.load_addr

        self.library = bool(self.pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL)
        self.executable = not self.library
        self.statically_linked = False
        self.dep = bool(
            optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        )
        self.aslr = bool(
            optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        )
        self.pie = self.aslr
        self.safeseh = None
        if hasattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            self.safeseh = bool(self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size)

        self._sections = [
            PESection(self, section) for section in self.pe.sections
        ]

        self._exports = {}
        self._import_rvas = {}
        self._thunk_rvas = {}
        self._import_dlls = {}
        self._relocation_entries = []

        self._parse_exports()
        self._parse_imports()
        self._find_import_thunks()
        self._parse_relocations()
        self._refresh_symbols()

    def _parse_exports(self):
        directory = getattr(self.pe, 'DIRECTORY_ENTRY_EXPORT', None)
        if not directory:
            return

        for export in directory.symbols:
            if not export.name or export.forwarder:
                continue
            name = _name(export.name)
            self._exports[name] = export.address

    def _parse_imports(self):
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        import_directories = []
        import_directories.extend(getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []))
        import_directories.extend(getattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', []))

        for dll in import_directories:
            dll_name = _name(dll.dll)
            for entry in dll.imports:
                if entry.name:
                    name = _name(entry.name)
                else:
                    name = 'ordinal_%d' % entry.ordinal

                rva = entry.address - image_base
                self._import_rvas[name] = rva
                self._import_dlls[name] = dll_name

    def _find_import_thunks(self):
        if not self._import_rvas:
            return

        iat_targets = {}
        for name, rva in self._import_rvas.items():
            iat_targets[self.load_addr + rva] = name

        for section in self._sections:
            if not section.executable or not section.raw_size:
                continue

            data = section.data
            section_va = self.load_addr + section.rva
            for offset in range(0, max(0, len(data) - 5)):
                if data[offset] != 0xff or data[offset + 1] not in (0x15, 0x25):
                    continue

                displacement = packing.u32(data[offset + 2:offset + 6])
                instruction_va = section_va + offset
                if self.bits == 64:
                    target = instruction_va + 6 + displacement
                    if displacement & 0x80000000:
                        target -= 1 << 32
                else:
                    target = displacement + (self.address - self.load_addr)

                name = iat_targets.get(target)
                if not name:
                    continue

                thunk_rva = section.rva + offset
                self._thunk_rvas[name] = thunk_rva
                self._thunk_rvas.setdefault('%s!%s' % (self._import_dlls[name], name), thunk_rva)

    def _parse_relocations(self):
        for block in getattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC', []):
            for entry in block.entries:
                self._relocation_entries.append((entry.rva, entry.type))

    def _refresh_symbols(self):
        self.symbols = {}
        self.imports = {}
        self.thunks = {}
        self.iat = self.imports

        for name, rva in self._exports.items():
            self.symbols[name] = self.address + rva

        for name, rva in self._import_rvas.items():
            self.imports[name] = self.address + rva
            qualified = '%s!%s' % (self._import_dlls[name], name)
            self.imports.setdefault(qualified, self.address + rva)

        for name, rva in self._thunk_rvas.items():
            self.thunks[name] = self.address + rva
            self.symbols[name] = self.address + rva

    @property
    def got(self):
        """Mapping of imported function names to their IAT slot addresses."""
        return self.imports

    @property
    def plt(self):
        """Mapping of imported function names to executable import thunks."""
        return self.thunks

    @property
    def address(self):
        """Runtime image base address."""
        return self._address

    @address.setter
    def address(self, value):
        self._address = int(value)
        self._refresh_symbols()

    @property
    def entry(self):
        return self.address + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    @property
    def entrypoint(self):
        return self.entry

    @property
    def entry_point(self):
        return self.entry

    @property
    def image_base(self):
        """Preferred image base stored in the optional header."""
        return self.load_addr

    @property
    def preferred_base(self):
        return self.load_addr

    @property
    def sections(self):
        return list(self._sections)

    @property
    def executable_sections(self):
        return [section for section in self._sections if section.executable]

    @property
    def writable_sections(self):
        return [section for section in self._sections if section.writable]

    @property
    def relocations(self):
        return [
            PERelocation(self, rva, reloc_type)
            for rva, reloc_type in self._relocation_entries
        ]

    @property
    def base_relocations(self):
        return self.relocations

    def resolve_import(self, name):
        """Resolve an imported function to its executable thunk if possible."""
        if name in self.thunks:
            return self.thunks[name]
        lowered = str(name).lower()
        for candidate, address in self.thunks.items():
            if str(candidate).lower() == lowered:
                return address
        if name in self.imports:
            return self.imports[name]
        for candidate, address in self.imports.items():
            if str(candidate).lower() == lowered:
                return address
        return None

    def get_section_by_name(self, name):
        if isinstance(name, bytes):
            name = _name(name)
        for section in self._sections:
            if section.name == name:
                return section
        return None

    def section(self, name):
        section = self.get_section_by_name(name)
        if section is None:
            return None
        return section.data

    def rva_to_offset(self, rva):
        size_of_headers = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        if rva < size_of_headers and rva < len(self.data):
            return rva

        for section in self._sections:
            size = max(section.virtual_size, section.raw_size)
            if section.rva <= rva < section.rva + size:
                offset = rva - section.rva
                if offset < section.raw_size:
                    return section.raw_offset + offset
                return None
        return None

    def vaddr_to_offset(self, address):
        return self.rva_to_offset(address - self.address)

    def read(self, address, count=1):
        """
        Read ``count`` bytes at a virtual address.

        Bytes in the virtual size but outside the raw section data are
        returned as zeroes, matching how Windows maps the image.
        """
        rva = address - self.address
        chunks = []
        remaining = count

        while remaining:
            if rva < self.pe.OPTIONAL_HEADER.SizeOfHeaders:
                offset = rva
                if offset >= len(self.data):
                    break
                chunk = self.data[offset:offset + remaining]
                if not chunk:
                    break
            else:
                section = next(
                    (
                        s for s in self._sections
                        if s.rva <= rva < s.rva + max(s.virtual_size, s.raw_size)
                    ),
                    None,
                )
                if section is None:
                    break

                offset = rva - section.rva
                raw = section.data
                if offset < len(raw):
                    chunk = raw[offset:offset + remaining]
                else:
                    chunk = b''

                virtual_remaining = max(0, min(
                    section.virtual_size - offset,
                    remaining - len(chunk),
                ))
                if virtual_remaining:
                    chunk += b'\x00' * virtual_remaining

                if not chunk:
                    break

            chunks.append(chunk)
            remaining -= len(chunk)
            rva += len(chunk)

        return b''.join(chunks)

    def search(self, needle, writable=False, executable=False):
        """Search mapped section data for ``needle``."""
        needle = packing._need_bytes(needle)
        for section in self._sections:
            if writable and not section.writable:
                continue
            if executable and not section.executable:
                continue

            data = section.data
            offset = 0
            while True:
                offset = data.find(needle, offset)
                if offset < 0:
                    break
                yield section.address + offset
                offset += 1

    def get_data(self):
        return self.data

    def save(self, path=None):
        if path is None:
            path = self.path
        with open(path, 'wb') as fd:
            fd.write(self.data)

    def disasm(self, address, n_bytes):
        return disasm(
            self.read(address, n_bytes),
            vma=address,
            arch=self.arch,
            endian=self.endian,
        )

    def close(self):
        pe = getattr(self, 'pe', None)
        if pe is not None:
            pe.close()
        if self._tempfile:
            try:
                os.unlink(self._tempfile)
            except OSError:
                pass
            self._tempfile = None

    def __del__(self):
        self.close()

    def __repr__(self):
        return 'PE(%r)' % self.path

    @classmethod
    def from_bytes(cls, data, *args, **kwargs):
        return cls(data, *args, **kwargs)
