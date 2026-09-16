import argparse
import ctypes
import ctypes.wintypes as wintypes
import os
import struct
import sys
from dataclasses import dataclass
from typing import Callable, Optional


# ============================================================
# Windows constants
# ============================================================

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


READABLE_PROTECTIONS = {
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}


# ============================================================
# WinAPI
# ============================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


# ============================================================
# Signature definitions
# ============================================================

@dataclass
class Signature:
    name: str
    category: str
    pattern: Optional[bytes] = None
    validator: Optional[Callable[[bytes, int], bool]] = None


SIGNATURES = [
    # --------------------------------------------------------
    # Images
    # --------------------------------------------------------

    Signature(
        "PNG",
        "image",
        b"\x89PNG\r\n\x1a\n",
    ),

    Signature(
        "JPEG",
        "image",
        b"\xff\xd8\xff",
    ),

    Signature(
        "GIF87a",
        "image",
        b"GIF87a",
    ),

    Signature(
        "GIF89a",
        "image",
        b"GIF89a",
    ),

    Signature(
        "BMP",
        "image",
        b"BM",
    ),

    Signature(
        "TIFF little-endian",
        "image",
        b"II\x2a\x00",
    ),

    Signature(
        "TIFF big-endian",
        "image",
        b"MM\x00\x2a",
    ),

    Signature(
        "ICO",
        "image",
        b"\x00\x00\x01\x00",
    ),

    Signature(
        "DDS",
        "image/texture",
        b"DDS ",
    ),

    Signature(
        "KTX",
        "image/texture",
        b"\xabKTX 11\xbb\r\n\x1a\n",
    ),

    Signature(
        "KTX2",
        "image/texture",
        b"\xabKTX 20\xbb\r\n\x1a\n",
    ),

    # --------------------------------------------------------
    # Audio
    # --------------------------------------------------------

    Signature(
        "FLAC",
        "audio",
        b"fLaC",
    ),

    Signature(
        "Ogg",
        "audio/container",
        b"OggS",
    ),

    Signature(
        "MP3 ID3",
        "audio",
        b"ID3",
    ),

    Signature(
        "MIDI",
        "audio",
        b"MThd",
    ),

    Signature(
        "AU",
        "audio",
        b".snd",
    ),

    # --------------------------------------------------------
    # Video / containers
    # --------------------------------------------------------

    Signature(
        "Matroska/WebM",
        "video/container",
        b"\x1a\x45\xdf\xa3",
    ),

    Signature(
        "AVI/WAV RIFF",
        "container",
        b"RIFF",
    ),

    Signature(
        "QuickTime atom",
        "video/container",
        b"moov",
    ),

    # --------------------------------------------------------
    # Compressed resources
    # Often useful because games/applications may retain them.
    # --------------------------------------------------------

    Signature(
        "ZIP",
        "archive",
        b"PK\x03\x04",
    ),

    Signature(
        "GZIP",
        "archive",
        b"\x1f\x8b\x08",
    ),

    Signature(
        "7-Zip",
        "archive",
        b"7z\xbc\xaf\x27\x1c",
    ),
]


# ============================================================
# Specialized detectors
# ============================================================

def detect_riff_type(data: bytes, offset: int) -> Optional[str]:
    """
    RIFF:
        00  RIFF
        04  size
        08  WAVE / AVI / WEBP
    """
    if offset + 12 > len(data):
        return None

    if data[offset:offset + 4] != b"RIFF":
        return None

    subtype = data[offset + 8:offset + 12]

    if subtype == b"WAVE":
        return "WAV"

    if subtype == b"AVI ":
        return "AVI"

    if subtype == b"WEBP":
        return "WEBP"

    return "RIFF"


def detect_iso_bmff(data: bytes, offset: int) -> Optional[str]:
    """
    ISO Base Media File Format.

    Common:
        [4-byte size] ftyp isom
        [4-byte size] ftyp mp42
        [4-byte size] ftyp M4A
    """
    if offset + 12 > len(data):
        return None

    if data[offset + 4:offset + 8] != b"ftyp":
        return None

    brand = data[offset + 8:offset + 12]

    if brand in (b"M4A ", b"M4B "):
        return "M4A/M4B"

    if brand in (
        b"isom",
        b"iso2",
        b"mp41",
        b"mp42",
        b"avc1",
        b"dash",
    ):
        return "MP4"

    if brand in (b"qt  ",):
        return "QuickTime"

    if brand in (b"heic", b"heix", b"hevc", b"hevx", b"mif1"):
        return "HEIF/HEIC"

    if brand in (b"avif", b"avis"):
        return "AVIF"

    return f"ISO-BMFF ({brand.decode('ascii', errors='replace')})"


def detect_mp3_frame(data: bytes, offset: int) -> bool:
    """
    Basic MPEG Audio frame-header validation.

    Not perfect, but substantially better than looking only
    for FF FB.
    """
    if offset + 4 > len(data):
        return False

    b1, b2, b3, b4 = data[offset:offset + 4]

    if b1 != 0xFF:
        return False

    # MPEG sync: first 11 bits set
    if (b2 & 0xE0) != 0xE0:
        return False

    version = (b2 >> 3) & 0x03

    # version 01 is reserved
    if version == 0x01:
        return False

    layer = (b2 >> 1) & 0x03

    # layer 00 reserved
    if layer == 0:
        return False

    bitrate_index = (b3 >> 4) & 0x0F

    # 0000 = free, 1111 = bad
    if bitrate_index in (0, 15):
        return False

    sample_rate_index = (b3 >> 2) & 0x03

    # 11 reserved
    if sample_rate_index == 3:
        return False

    return True


# ============================================================
# Hex dump
# ============================================================

def hexdump(data: bytes, base_address: int, width: int = 16) -> str:
    lines = []

    for i in range(0, len(data), width):
        chunk = data[i:i + width]

        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(
            chr(b) if 32 <= b <= 126 else "."
            for b in chunk
        )

        lines.append(
            f"{base_address + i:016X}  "
            f"{hex_part:<{width * 3}} "
            f"{ascii_part}"
        )

    return "\n".join(lines)


# ============================================================
# Search
# ============================================================

def find_all(data: bytes, pattern: bytes):
    start = 0

    while True:
        index = data.find(pattern, start)

        if index == -1:
            break

        yield index

        start = index + 1


def scan_chunk(
    data: bytes,
    base_address: int,
    dump_bytes: int,
    seen: set,
):
    results = []

    # --------------------------------------------------------
    # Fixed signatures
    # --------------------------------------------------------

    for signature in SIGNATURES:
        if not signature.pattern:
            continue

        for offset in find_all(data, signature.pattern):

            address = base_address + offset

            # RIFF gets specialized interpretation.
            if signature.pattern == b"RIFF":
                detected_name = detect_riff_type(data, offset)
                name = detected_name or signature.name

            else:
                name = signature.name

            key = (address, name)

            if key in seen:
                continue

            seen.add(key)

            start = max(0, offset - dump_bytes)
            end = min(len(data), offset + dump_bytes)

            results.append(
                (
                    address,
                    name,
                    signature.category,
                    data[start:end],
                    base_address + start,
                )
            )

    # --------------------------------------------------------
    # ISO BMFF: MP4, M4A, HEIC, AVIF...
    #
    # Search for FTYP but actual beginning is 4 bytes earlier.
    # --------------------------------------------------------

    for ftyp_offset in find_all(data, b"ftyp"):

        offset = ftyp_offset - 4

        if offset < 0:
            continue

        detected = detect_iso_bmff(data, offset)

        if not detected:
            continue

        address = base_address + offset
        key = (address, detected)

        if key in seen:
            continue

        seen.add(key)

        start = max(0, offset - dump_bytes)
        end = min(len(data), offset + dump_bytes)

        results.append(
            (
                address,
                detected,
                "media/container",
                data[start:end],
                base_address + start,
            )
        )

    # --------------------------------------------------------
    # MPEG Audio / MP3 frames
    # --------------------------------------------------------

    offset = 0

    while True:
        offset = data.find(b"\xff", offset)

        if offset == -1:
            break

        if detect_mp3_frame(data, offset):

            address = base_address + offset
            key = (address, "MPEG Audio frame")

            if key not in seen:

                seen.add(key)

                start = max(0, offset - dump_bytes)
                end = min(len(data), offset + dump_bytes)

                results.append(
                    (
                        address,
                        "MPEG Audio frame",
                        "audio",
                        data[start:end],
                        base_address + start,
                    )
                )

        offset += 1

    return results


# ============================================================
# Process memory scanning
# ============================================================

def is_readable_region(mbi: MEMORY_BASIC_INFORMATION) -> bool:

    if mbi.State != MEM_COMMIT:
        return False

    if mbi.Protect & PAGE_GUARD:
        return False

    if mbi.Protect & PAGE_NOACCESS:
        return False

    base_protection = mbi.Protect & 0xFF

    return base_protection in READABLE_PROTECTIONS


def read_memory(
    process_handle,
    address: int,
    size: int,
) -> Optional[bytes]:

    if size <= 0:
        return None

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()

    success = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )

    if not success or bytes_read.value == 0:
        return None

    return buffer.raw[:bytes_read.value]


def scan_process(
    pid: int,
    chunk_size: int,
    dump_bytes: int,
):

    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid,
    )

    if not handle:
        error = ctypes.get_last_error()

        raise OSError(
            error,
            f"OpenProcess failed for PID {pid}: "
            f"{ctypes.FormatError(error)}"
        )

    print(f"PID: {pid}")
    print(f"Chunk size: {chunk_size:,} bytes")
    print()

    mbi = MEMORY_BASIC_INFORMATION()

    address = 0

    scanned_regions = 0
    scanned_bytes = 0
    hits = 0

    seen = set()

    # Enough overlap to catch headers split between chunks.
    overlap = 64

    try:

        while True:

            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

            if result == 0:
                break

            region_base = int(mbi.BaseAddress or 0)
            region_size = int(mbi.RegionSize)

            if is_readable_region(mbi):

                scanned_regions += 1

                position = 0

                while position < region_size:

                    size = min(
                        chunk_size,
                        region_size - position
                    )

                    current_address = region_base + position

                    data = read_memory(
                        handle,
                        current_address,
                        size,
                    )

                    if data:

                        scanned_bytes += len(data)

                        results = scan_chunk(
                            data,
                            current_address,
                            dump_bytes,
                            seen,
                        )

                        for (
                            hit_address,
                            name,
                            category,
                            dump,
                            dump_address,
                        ) in results:

                            hits += 1

                            print(
                                f"[{name}] "
                                f"{category}"
                            )

                            print(
                                f"Address: "
                                f"0x{hit_address:016X}"
                            )

                            print(
                                hexdump(
                                    dump,
                                    dump_address
                                )
                            )

                            print("-" * 80)

                    if size <= overlap:
                        position += size
                    else:
                        position += size - overlap

            next_address = region_base + region_size

            if next_address <= address:
                break

            address = next_address

    finally:
        kernel32.CloseHandle(handle)

    print()
    print("=" * 80)
    print("SCAN COMPLETE")
    print(f"Readable regions: {scanned_regions:,}")
    print(f"Bytes scanned:    {scanned_bytes:,}")
    print(f"Signatures found: {hits:,}")


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Scan the memory of a Windows process "
            "for common multimedia file signatures."
        )
    )

    parser.add_argument(
        "pid",
        type=int,
        help="PID of the target process",
    )

    parser.add_argument(
        "--chunk-size",
        type=int,
        default=4 * 1024 * 1024,
        help=(
            "Read chunk size in bytes "
            "(default: 4 MiB)"
        ),
    )

    parser.add_argument(
        "--dump-bytes",
        type=int,
        default=64,
        help=(
            "Bytes around each match shown in hex "
            "(default: 64)"
        ),
    )

    args = parser.parse_args()

    if os.name != "nt":
        print(
            "This script currently supports Windows only.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        scan_process(
            pid=args.pid,
            chunk_size=args.chunk_size,
            dump_bytes=args.dump_bytes,
        )

    except KeyboardInterrupt:
        print("\nInterrupted.")

    except Exception as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()