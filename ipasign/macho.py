"""Mach-O container parsing and rewriting.

A Mach-O file is either thin (one slice) or fat (several slices behind a fat
header). Everything here works on an in-memory ``bytes`` buffer and hands out
views into it, so a caller can read a binary once and sign it without a second
pass over the file.

Only what signing needs is modelled: the header, the load commands worth
looking at, the segments that carry a signature and the embedded info plist.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .errors import MachOError, NotEnoughSpaceError

# Header magics, as seen when the first four bytes are read little-endian.
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

# Fat headers are detected on their raw bytes. The canonical order
# ``ca fe ba be`` stores its fields big-endian; the byte-swapped form stores
# them little-endian. Getting this backwards rejects real Apple frameworks.
FAT_MAGIC_BYTES = b"\xca\xfe\xba\xbe"
FAT_CIGAM_BYTES = b"\xbe\xba\xfe\xca"

THIN_MAGICS = (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64)

MH_EXECUTE = 0x2

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

FAT_ALIGN_SHIFT = 14  # 16384-byte slice alignment
SIGNATURE_ALIGN = 4096

_HEADER_SIZE = {False: 28, True: 32}
_SEGMENT_SIZE = {False: 56, True: 72}
_SECTION_SIZE = {False: 68, True: 80}

# name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags
_SEGMENT = {False: "16s8I", True: "16s4Q4I"}
# sectname, segname, addr, size, offset, align, reloff, nreloc, flags, reserved
_SECTION = {False: "16s16s9I", True: "16s16s2Q8I"}


def _cstr(raw: bytes) -> str:
    """Decode a fixed-size NUL-padded name field."""
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


@dataclass(slots=True)
class Section:
    """One entry of a segment's section table."""

    name: str
    segname: str
    addr: int
    size: int
    offset: int
    align: int
    reloff: int
    nreloc: int
    flags: int


@dataclass(slots=True)
class Segment:
    """A load command describing one segment."""

    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    flags: int
    sections: list[Section]
    command_offset: int
    command_size: int
    is_64: bool

    def section(self, name: str) -> Section | None:
        for sect in self.sections:
            if sect.name == name:
                return sect
        return None


@dataclass(slots=True)
class LoadCommand:
    """A load command this library has an opinion about."""

    cmd: int
    size: int
    offset: int
    data: tuple[int, ...] = ()


@dataclass(slots=True)
class Slice:
    """One architecture of a Mach-O file, pointing back at the source buffer."""

    data: bytes
    base: int
    size: int
    big_endian: bool
    is_64: bool
    cpu_type: int
    cpu_subtype: int
    file_type: int
    ncmds: int
    sizeofcmds: int
    flags: int
    segments: list[Segment] = field(default_factory=list)
    commands: list[LoadCommand] = field(default_factory=list)
    code_signature: LoadCommand | None = None
    info_plist: bytes = b""
    encrypted: bool = False

    @property
    def endian(self) -> str:
        return ">" if self.big_endian else "<"

    @property
    def header_size(self) -> int:
        return _HEADER_SIZE[self.is_64]

    @property
    def view(self) -> memoryview:
        """The slice's bytes as a view, without copying."""
        return memoryview(self.data)[self.base : self.base + self.size]

    @property
    def is_execute(self) -> bool:
        return self.file_type == MH_EXECUTE

    @property
    def code_length(self) -> int:
        """Where the signature region starts.

        For a signed file that is ``LC_CODE_SIGNATURE.dataoff``. For an unsigned
        one it is the file size rounded up to a 16-byte boundary, which is where
        a signature would be appended.
        """
        if self.code_signature is not None:
            return self.code_signature.data[0]
        return round_up(self.size, 16)

    @property
    def signature_length(self) -> int:
        """Length of the existing signature region, zero when unsigned.

        Code signature blobs are always big-endian, whatever the Mach-O header
        says, so the length field is read big-endian here.
        """
        if self.code_signature is None:
            return 0
        start = self.code_signature.data[0]
        if start + 8 > self.size:
            return 0
        return struct.unpack_from(">I", self.data, self.base + start + 4)[0]

    @property
    def text_segment(self) -> Segment | None:
        for seg in self.segments:
            if seg.name == "__TEXT":
                return seg
        return None

    @property
    def linkedit_segment(self) -> Segment | None:
        for seg in self.segments:
            if seg.name == "__LINKEDIT":
                return seg
        return None

    @property
    def load_commands_free_space(self) -> int:
        """Bytes between the end of the load commands and the first section data."""
        text = self.text_segment
        if text is None:
            return 0
        text_sect = text.section("__text")
        if text_sect is None or text_sect.offset <= self.header_size + self.sizeofcmds:
            return 0
        return text_sect.offset - self.header_size - self.sizeofcmds

    @property
    def exec_seg_limit(self) -> int:
        """The ``__TEXT`` segment vmsize, sealed into the CodeDirectory."""
        text = self.text_segment
        return text.vmsize if text is not None else 0


def _parse_slice(data: bytes, base: int, size: int) -> Slice:
    if base + size > len(data):
        raise MachOError("slice runs past the end of the file")
    magic = struct.unpack_from("<I", data, base)[0]
    if magic not in THIN_MAGICS:
        raise MachOError(f"not a Mach-O magic at offset {base}: 0x{magic:08x}")

    big_endian = magic in (MH_CIGAM, MH_CIGAM_64)
    is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    endian = ">" if big_endian else "<"

    fields = struct.unpack_from(endian + ("8I" if is_64 else "7I"), data, base)
    slc = Slice(
        data=data,
        base=base,
        size=size,
        big_endian=big_endian,
        is_64=is_64,
        cpu_type=fields[1],
        cpu_subtype=fields[2],
        file_type=fields[3],
        ncmds=fields[4],
        sizeofcmds=fields[5],
        flags=fields[6],
    )

    # Parsing walks absolute file offsets; everything stored on the dataclasses is
    # relative to the slice base, because the writers rebuild a slice-only buffer.
    cursor = base + _HEADER_SIZE[is_64]
    for _ in range(slc.ncmds):
        if cursor + 8 > base + size:
            raise MachOError("load command runs past the end of the slice")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > base + size:
            raise MachOError(f"bad load command size {cmdsize} for cmd 0x{cmd:x}")

        offset = cursor - base
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            slc.segments.append(_parse_segment(data, cursor, offset, cmd == LC_SEGMENT_64, endian))
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from(endian + "II", data, cursor + 8)
            slc.code_signature = LoadCommand(cmd, cmdsize, offset, (dataoff, datasize))
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            cryptid = struct.unpack_from(endian + "I", data, cursor + 16)[0]
            slc.encrypted = cryptid >= 1
            slc.commands.append(LoadCommand(cmd, cmdsize, offset))
        else:
            slc.commands.append(LoadCommand(cmd, cmdsize, offset))

        cursor += cmdsize

    text = slc.text_segment
    if text is not None:
        info = text.section("__info_plist")
        if info is not None and info.offset and info.size:
            slc.info_plist = bytes(data[base + info.offset : base + info.offset + info.size])

    return slc


def _parse_segment(data: bytes, cursor: int, offset: int, is_64: bool, endian: str) -> Segment:
    fields = struct.unpack_from(endian + _SEGMENT[is_64], data, cursor + 8)
    name = _cstr(fields[0])
    vmaddr, vmsize, fileoff, filesize = fields[1:5]
    maxprot, initprot, nsects, flags = fields[5:9]
    command_size = struct.unpack_from(endian + "I", data, cursor + 4)[0]

    sections: list[Section] = []
    sect_off = cursor + _SEGMENT_SIZE[is_64]
    for _ in range(nsects):
        raw = struct.unpack_from(endian + _SECTION[is_64], data, sect_off)
        sections.append(
            Section(
                name=_cstr(raw[0]),
                segname=_cstr(raw[1]),
                addr=raw[2],
                size=raw[3],
                offset=raw[4],
                align=raw[5],
                reloff=raw[6],
                nreloc=raw[7],
                flags=raw[8],
            )
        )
        sect_off += _SECTION_SIZE[is_64]

    return Segment(
        name=name,
        vmaddr=vmaddr,
        vmsize=vmsize,
        fileoff=fileoff,
        filesize=filesize,
        maxprot=maxprot,
        initprot=initprot,
        flags=flags,
        sections=sections,
        command_offset=offset,
        command_size=command_size,
        is_64=is_64,
    )


@dataclass(slots=True)
class FatArch:
    """One entry of a fat header."""

    cpu_type: int
    cpu_subtype: int
    offset: int
    size: int
    align: int


@dataclass(slots=True)
class MachOFile:
    """A parsed Mach-O file, thin or fat.

    ``data`` is the original buffer and stays untouched, so a failed sign cannot
    leave a half-written binary behind.
    """

    data: bytes
    is_fat: bool
    fat_big_endian: bool
    slices: list[Slice]
    archs: list[FatArch] = field(default_factory=list)

    @classmethod
    def parse(cls, data: bytes) -> "MachOFile":
        try:
            return cls._parse(data)
        except struct.error as exc:
            # struct.error is not part of the public API: a truncated or
            # malformed binary becomes a MachOError at the boundary.
            raise MachOError(f"malformed Mach-O: {exc}") from exc

    @classmethod
    def _parse(cls, data: bytes) -> "MachOFile":
        if len(data) < 8:
            raise MachOError("file is too short to be a Mach-O")
        head = bytes(data[:4])
        if head in (FAT_MAGIC_BYTES, FAT_CIGAM_BYTES):
            return cls._parse_fat(data, head == FAT_MAGIC_BYTES)
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in THIN_MAGICS:
            return cls(
                data=data,
                is_fat=False,
                fat_big_endian=False,
                slices=[_parse_slice(data, 0, len(data))],
            )
        raise MachOError(f"unrecognised Mach-O magic 0x{magic:08x}")

    @classmethod
    def _parse_fat(cls, data: bytes, big_endian: bool) -> "MachOFile":
        endian = ">" if big_endian else "<"
        if len(data) < 8:
            raise MachOError("fat header is truncated")
        nfat = struct.unpack_from(endian + "I", data, 4)[0]
        if len(data) < 8 + nfat * 20:
            raise MachOError(f"fat header claims {nfat} architectures but is truncated")
        archs: list[FatArch] = []
        slices: list[Slice] = []
        for i in range(nfat):
            cputype, cpusubtype, offset, size, align = struct.unpack_from(
                endian + "5I", data, 8 + i * 20
            )
            if offset + size > len(data):
                raise MachOError(f"fat arch {i} runs past the end of the file")
            archs.append(FatArch(cputype, cpusubtype, offset, size, align))
            slices.append(_parse_slice(data, offset, size))
        return cls(data=data, is_fat=True, fat_big_endian=big_endian, slices=slices, archs=archs)


def align_up(value: int, align: int) -> int:
    """Round ``value`` up to a multiple of ``align``, never a no-op."""
    return value + (align - value % align)


def round_up(value: int, align: int) -> int:
    """Round ``value`` up to a multiple of ``align``, a no-op when already aligned."""
    return value if value % align == 0 else value + align - value % align


def signature_region_size(code_length: int) -> int:
    """How much room to reserve for a signature starting at ``code_length``.

    One slot per page for both SHA-1 and SHA-256, plus a fixed tail for the
    SuperBlob header, Requirements, Entitlements and the CMS blob.
    """
    return align_up(((code_length // SIGNATURE_ALIGN) + 1) * (20 + 32), SIGNATURE_ALIGN) + 32768


def grow_slice(slc: Slice, new_length: int) -> bytes:
    """Return the slice resized to ``new_length`` with room for a signature.

    The signature region itself is left as zero padding; call
    :func:`place_signature` once the blob is built. ``__LINKEDIT`` and
    ``LC_CODE_SIGNATURE`` are brought up to date here.
    """
    if new_length < slc.size:
        raise MachOError("cannot shrink a slice to make room for a signature")

    out = bytearray(slc.view)
    out.extend(b"\0" * (new_length - len(out)))

    code_length = slc.code_length
    _set_signature_command(slc, out, code_length, new_length - code_length)

    if new_length > slc.size:
        _grow_linkedit(slc, out, new_length)

    return bytes(out)


def place_signature(slc: Slice, data: bytes, code_length: int, signature: bytes) -> bytes:
    """Write ``signature`` into a slice previously sized by :func:`grow_slice`."""
    out = bytearray(data)
    end = code_length + len(signature)
    if end > len(out) or code_length < 0:
        raise MachOError("signature does not fit in the region it was sized for")
    out[code_length:end] = signature
    _set_signature_command(slc, out, code_length, len(out) - code_length)
    return bytes(out)


def _set_signature_command(slc: Slice, out: bytearray, code_length: int, region: int) -> None:
    """Create or update the ``LC_CODE_SIGNATURE`` load command."""
    endian = slc.endian
    if slc.code_signature is None:
        if slc.load_commands_free_space < 16:
            raise NotEnoughSpaceError(
                "no room in the load commands for LC_CODE_SIGNATURE; "
                f"{slc.load_commands_free_space} bytes free, 16 needed"
            )
        cmd_off = slc.header_size + slc.sizeofcmds
        struct.pack_into(endian + "IIII", out, cmd_off, LC_CODE_SIGNATURE, 16, code_length, region)
        struct.pack_into(endian + "I", out, 16, slc.ncmds + 1)
        struct.pack_into(endian + "I", out, 20, slc.sizeofcmds + 16)
    else:
        struct.pack_into(endian + "II", out, slc.code_signature.offset + 8, code_length, region)


def _grow_linkedit(slc: Slice, out: bytearray, new_length: int) -> None:
    """Extend ``__LINKEDIT`` to cover the grown file."""
    linkedit = slc.linkedit_segment
    if linkedit is None:
        raise MachOError("slice has no __LINKEDIT segment")
    endian = slc.endian
    grow = new_length - slc.size
    if linkedit.is_64:
        vmsize = align_up(linkedit.vmsize + grow, SIGNATURE_ALIGN)
        struct.pack_into(endian + "Q", out, linkedit.command_offset + 32, vmsize)
        struct.pack_into(endian + "Q", out, linkedit.command_offset + 48, new_length - linkedit.fileoff)
    else:
        vmsize = align_up((linkedit.vmsize + grow) & 0xFFFFFFFF, SIGNATURE_ALIGN)
        struct.pack_into(endian + "I", out, linkedit.command_offset + 28, vmsize)
        struct.pack_into(endian + "I", out, linkedit.command_offset + 36, new_length - linkedit.fileoff)


def build_fat(
    slices: list[bytes],
    archs: list[FatArch],
    big_endian: bool,
    align: int = 1 << FAT_ALIGN_SHIFT,
) -> bytes:
    """Lay slices out behind a fat header at ``align`` and return the container."""
    if len(slices) != len(archs):
        raise MachOError("slice count does not match fat arch count")

    endian = ">" if big_endian else "<"
    magic = FAT_MAGIC_BYTES if big_endian else FAT_CIGAM_BYTES
    offset = align_up(8 + 20 * len(archs), align)

    out = bytearray(b"\0" * offset)
    out[0:4] = magic
    struct.pack_into(endian + "I", out, 4, len(archs))

    for i, (blob, arch) in enumerate(zip(slices, archs)):
        if len(out) < offset:
            out.extend(b"\0" * (offset - len(out)))
        out[offset : offset + len(blob)] = blob
        struct.pack_into(
            endian + "5I",
            out,
            8 + i * 20,
            arch.cpu_type,
            arch.cpu_subtype,
            offset,
            len(blob),
            FAT_ALIGN_SHIFT,
        )
        offset = align_up(offset + len(blob), align)

    if len(out) < offset:
        out.extend(b"\0" * (offset - len(out)))
    return bytes(out)


__all__ = [
    "MachOFile",
    "Slice",
    "Segment",
    "Section",
    "FatArch",
    "LoadCommand",
    "align_up",
    "round_up",
    "signature_region_size",
    "grow_slice",
    "place_signature",
    "build_fat",
    "MH_EXECUTE",
    "LC_CODE_SIGNATURE",
]
