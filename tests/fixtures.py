"""Synthetic fixtures for the test suite.

Everything here builds its own inputs, so the tests run without the sample IPA
or the certificate under ``__test/``. Scratch files live under ``tests/.scratch``
and are removed by the tests that create them.
"""

from __future__ import annotations

import plistlib
import shutil
import struct
import zipfile
import zlib
from pathlib import Path

from asn1crypto import core

from ipasign.macho import MH_EXECUTE, round_up

SCRATCH = Path(__file__).resolve().parent / ".scratch"

HEADER_SIZE = 32
TEXT_CMD_SIZE = 72 + 80  # segment_command_64 plus one section_64
LINKEDIT_CMD_SIZE = 72
SIZEOFCMDS = TEXT_CMD_SIZE + LINKEDIT_CMD_SIZE

TEXT_OFFSET = 1024
TEXT_SIZE = 7168
TEXT_END = TEXT_OFFSET + TEXT_SIZE
LINKEDIT_OFFSET = round_up(TEXT_END, 16)
FILE_SIZE = LINKEDIT_OFFSET


def scratch_dir(name: str) -> Path:
    """A fresh scratch directory for one test."""
    path = SCRATCH / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def minimal_macho(file_type: int = MH_EXECUTE, cpu_type: int = 0x0100000C) -> bytes:
    """A tiny but structurally valid 64-bit Mach-O with no signature.

    One ``__TEXT`` segment holding a ``__text`` section, one empty
    ``__LINKEDIT``, and enough free space after the load commands for a new
    ``LC_CODE_SIGNATURE`` to be appended.
    """
    text_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,  # LC_SEGMENT_64
        TEXT_CMD_SIZE,
        b"__TEXT".ljust(16, b"\0"),
        0x100000000,  # vmaddr
        TEXT_END,  # vmsize
        0,  # fileoff
        TEXT_END,  # filesize
        7,  # maxprot
        5,  # initprot
        1,  # nsects
        0,  # flags
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"),
        0x100000000 + TEXT_OFFSET,  # addr
        TEXT_SIZE,  # size
        TEXT_OFFSET,  # offset
        0,  # align
        0,  # reloff
        0,  # nreloc
        0x80000400,  # flags: S_ATTR_PURE_INSTRUCTIONS
        0,
        0,
        0,
    )
    linkedit_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,  # LC_SEGMENT_64
        LINKEDIT_CMD_SIZE,
        b"__LINKEDIT".ljust(16, b"\0"),
        0x100000000 + LINKEDIT_OFFSET,  # vmaddr
        0,  # vmsize
        LINKEDIT_OFFSET,  # fileoff
        0,  # filesize
        7,
        1,
        0,  # nsects
        0,
    )

    header = struct.pack(
        "<8I",
        0xFEEDFACF,  # MH_MAGIC_64
        cpu_type,
        0,  # cpusubtype
        file_type,
        2,  # ncmds
        SIZEOFCMDS,
        0x00200085,  # flags
        0,  # reserved
    )

    body = bytearray(b"\0" * FILE_SIZE)
    body[0:HEADER_SIZE] = header
    body[HEADER_SIZE : HEADER_SIZE + TEXT_CMD_SIZE] = text_cmd + section
    body[HEADER_SIZE + TEXT_CMD_SIZE : HEADER_SIZE + SIZEOFCMDS] = linkedit_cmd
    body[TEXT_OFFSET:TEXT_END] = b"\x90" * TEXT_SIZE
    return bytes(body)


def minimal_fat(*slices: bytes, big_endian: bool = True) -> bytes:
    """Wrap slices in a fat header, laid out at the usual 16384 alignment."""
    from ipasign.macho import FAT_MAGIC_BYTES, FAT_CIGAM_BYTES, align_up

    endian = ">" if big_endian else "<"
    magic = FAT_MAGIC_BYTES if big_endian else FAT_CIGAM_BYTES
    offset = align_up(8 + 20 * len(slices), 16384)

    out = bytearray(b"\0" * offset)
    out[0:4] = magic
    struct.pack_into(endian + "I", out, 4, len(slices))
    for i, blob in enumerate(slices):
        if len(out) < offset:
            out.extend(b"\0" * (offset - len(out)))
        out[offset : offset + len(blob)] = blob
        struct.pack_into(endian + "5I", out, 8 + i * 20, 0x0100000C, 0, offset, len(blob), 14)
        offset = align_up(offset + len(blob), 16384)
    if len(out) < offset:
        out.extend(b"\0" * (offset - len(out)))
    return bytes(out)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(kind + payload)
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)

def _filter_rows(rows: list[bytes], kind: int) -> bytes:
    """Filter each row and prefix it with the filter byte, as an encoder does."""
    out = bytearray()
    previous = bytes(len(rows[0]))
    for row in rows:
        out.append(kind)
        if kind == 0:
            out += row
        elif kind == 1:
            out += bytes((row[i] - (row[i - 4] if i >= 4 else 0)) & 0xFF for i in range(len(row)))
        elif kind == 2:
            out += bytes((row[i] - previous[i]) & 0xFF for i in range(len(row)))
        elif kind == 3:
            out += bytes(
                (row[i] - (((row[i - 4] if i >= 4 else 0) + previous[i]) >> 1)) & 0xFF
                for i in range(len(row))
            )
        elif kind == 4:
            out += bytes(
                (
                    row[i]
                    - _paeth(
                        row[i - 4] if i >= 4 else 0,
                        previous[i],
                        previous[i - 4] if i >= 4 else 0,
                    )
                )
                & 0xFF
                for i in range(len(row))
            )
        else:
            raise ValueError(f"no such PNG filter: {kind}")
        previous = row
    return bytes(out)

def _paeth(a: int, b: int, c: int) -> int:
    estimate = a + b - c
    pa, pb, pc = abs(estimate - a), abs(estimate - b), abs(estimate - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c

def standard_png(rows: list[bytes], filter_kind: int = 0) -> bytes:
    """An 8-bit RGBA PNG, one byte per channel.

    ``rows`` holds raw RGBA bytes; ``filter_kind`` selects the PNG filter the
    encoder applies to every row, exactly one of 0 to 4.
    """
    width = len(rows[0]) // 4
    ihdr = struct.pack(">IIBBBBB", width, len(rows), 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(_filter_rows(rows, filter_kind)))
        + _png_chunk(b"IEND", b"")
    )

def cgbi_png(rows: list[bytes], filter_kind: int = 0) -> bytes:
    """The same image crushed the way ``pngcrush -iphone`` would.

    Takes raw RGBA rows and emits Apple's variant: a ``CgBI`` chunk, a
    headerless deflate stream, and BGRA pixels with premultiplied alpha. The
    crush happens first and the filter is applied to the crushed bytes, which
    is the order pngcrush uses and the reverse of what the decoder does.
    """
    width = len(rows[0]) // 4
    ihdr = struct.pack(">IIBBBBB", width, len(rows), 8, 6, 0, 0, 0)

    crushed = []
    for row in rows:
        out = bytearray()
        for i in range(0, len(row), 4):
            red, green, blue, alpha = row[i : i + 4]
            if 0 < alpha < 255:
                red = (red * alpha + 127) // 255
                green = (green * alpha + 127) // 255
                blue = (blue * alpha + 127) // 255
            out += bytes((blue, green, red, alpha))
        crushed.append(bytes(out))

    deflate = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
    payload = deflate.compress(_filter_rows(crushed, filter_kind)) + deflate.flush()
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"CgBI", b"\0\0\0\0")
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", payload)
        + _png_chunk(b"IEND", b"")
    )

def info_plist(**overrides) -> bytes:
    """A minimal ``Info.plist`` for a fake bundle."""
    info = {
        "CFBundleIdentifier": "com.example.test",
        "CFBundleExecutable": "Test",
        "CFBundleName": "Test",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
    }
    info.update(overrides)
    return plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=False)


def fake_bundle(root: Path, *, executable: bytes | None = None, **plist_overrides) -> Path:
    """Create a bundle directory with an Info.plist and an executable."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "Info.plist").write_bytes(info_plist(**plist_overrides))
    (root / "Test").write_bytes(executable if executable is not None else minimal_macho())
    (root / "Resource.txt").write_text("hello\n")
    return root


def fake_ipa(path: Path, app_name: str = "Test.app", **plist_overrides) -> Path:
    """Create an .ipa archive holding one app bundle.

    The executable entry carries an execute mode, the way a real archive does,
    so the unpack round trip can be checked for permission preservation.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"Payload/{app_name}"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{prefix}/Info.plist", info_plist(**plist_overrides))
        archive.writestr(f"{prefix}/Resource.txt", "hello\n")

        executable = zipfile.ZipInfo(f"{prefix}/Test")
        executable.external_attr = 0o100755 << 16
        executable.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(executable, minimal_macho())
    return path


def mobileprovision(
    *,
    team_id: str = "TEAM123456",
    app_id: str = "TEAM123456.com.example.test",
    entitlements: dict | None = None,
    developer_certificates: list[bytes] | None = None,
    include_team: bool = True,
    include_entitlements: bool = True,
) -> bytes:
    """A minimal CMS-wrapped provisioning profile, without a real signature.

    The structure is what ``load_profile`` walks: a ``signed_data`` container
    whose encapsulated content is the profile plist. Nothing verifies the CMS
    signature, which is fine because neither does the loader.
    """
    from asn1crypto import cms

    if entitlements is None:
        entitlements = {
            "application-identifier": app_id,
            "get-task-allow": False,
        }

    profile = {
        "Name": "Test Profile",
        "UUID": "00000000-0000-0000-0000-000000000000",
        "TeamIdentifier": [team_id] if include_team else [],
        "DeveloperCertificates": developer_certificates or [],
        "Entitlements": entitlements if include_entitlements else None,
    }
    if profile["Entitlements"] is None:
        del profile["Entitlements"]

    payload = plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=False)
    return cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": cms.SignedData(
                {
                    "version": "v1",
                    "digest_algorithms": [],
                    "encap_content_info": cms.ContentInfo(
                        {"content_type": "data", "content": core.OctetString(payload)}
                    ),
                    "signer_infos": [],
                }
            ),
        }
    ).dump()


def adhoc_key():
    """A credential-less key, for tests that only need a signature to exist."""
    from ipasign.key import Key

    return Key(adhoc=True)

def test_code_directory(size: int = 256) -> bytes:
    """A stand-in CodeDirectory blob, enough for CMS tests to hash."""
    import struct as _struct

    body = bytes(range(256))[: max(0, size - 8)]
    blob = bytearray()
    blob += b"\xfa\xde\x0c\x02"
    blob += _struct.pack(">I", 8 + len(body))
    blob += body
    return bytes(blob)


def test_identity(cn: str = "Test Signer"):
    """A throwaway RSA identity: self-signed leaf, no real chain.

    RSA keygen takes around a tenth of a second, so this is generated once per
    call and cached by the caller when reused.
    """
    import datetime as _datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from ipasign.credentials import Identity

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _datetime.datetime.now(_datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _datetime.timedelta(days=1))
        .sign(key, _hashes.SHA256())
    )
    return Identity(private_key=key, certificate=cert, chain=[cert])


def issued_by(issuer_cert, cn: str = "Leaf"):
    """A throwaway identity whose leaf is issued by ``issuer_cert``.

    The signature is real (signed with the leaf's own key), but the issuer does
    not verify it. That is fine: ``_select_chain`` matches on subject names, and
    nothing in these tests walks the chain cryptographically.
    """
    import datetime as _datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from ipasign.credentials import Identity

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _datetime.datetime.now(_datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _datetime.timedelta(days=1))
        .sign(key, _hashes.SHA256())
    )
    return Identity(private_key=key, certificate=cert, chain=[issuer_cert, cert])


def macho_with_info_plist(info: dict, *, file_type: int = MH_EXECUTE) -> bytes:
    """A minimal Mach-O carrying an ``__info_plist`` section.

    Adds a second section to ``__TEXT`` holding the plist bytes, placed after
    ``__text`` so the free space in front of the first section is unchanged.
    """
    plist_bytes = plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=False)
    plist_offset = round_up(TEXT_END, 16)
    plist_size = len(plist_bytes)
    text_vmsize = plist_offset + plist_size
    text_cmd_size = 72 + 2 * 80  # two sections now
    sizeofcmds = text_cmd_size + LINKEDIT_CMD_SIZE
    linkedit_offset = round_up(text_vmsize, 16)
    file_size = linkedit_offset

    text_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        text_cmd_size,
        b"__TEXT".ljust(16, b"\0"),
        0x100000000,
        text_vmsize,
        0,
        text_vmsize,
        7,
        5,
        2,
        0,
    )
    text_section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"),
        0x100000000 + TEXT_OFFSET,
        TEXT_SIZE,
        TEXT_OFFSET,
        0,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    plist_section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__info_plist".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"),
        0x100000000 + plist_offset,
        plist_size,
        plist_offset,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    linkedit_cmd = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        LINKEDIT_CMD_SIZE,
        b"__LINKEDIT".ljust(16, b"\0"),
        0x100000000 + linkedit_offset,
        0,
        linkedit_offset,
        0,
        7,
        1,
        0,
        0,
    )
    header = struct.pack(
        "<8I", 0xFEEDFACF, 0x0100000C, 0, file_type, 2, sizeofcmds, 0x00200085, 0
    )

    body = bytearray(b"\0" * file_size)
    body[0:HEADER_SIZE] = header
    body[HEADER_SIZE : HEADER_SIZE + text_cmd_size] = text_cmd + text_section + plist_section
    body[HEADER_SIZE + text_cmd_size : HEADER_SIZE + sizeofcmds] = linkedit_cmd
    body[TEXT_OFFSET:TEXT_END] = b"\x90" * TEXT_SIZE
    body[plist_offset : plist_offset + plist_size] = plist_bytes
    return bytes(body)
