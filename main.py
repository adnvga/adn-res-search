import argparse
import ctypes
import sys
from ctypes import wintypes


if sys.platform != "win32":
    raise SystemExit("Este programa solo es compatible con Windows.")


PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD = 0x1000, 0x01, 0x100
PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY = 0x02, 0x04, 0x08
PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY = 0x20, 0x40, 0x80
READABLE_PROTECTIONS = {PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


SIGNATURES = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "BMP": b"BM",
    "TIFF little-endian": b"II\x2a\x00",
    "TIFF big-endian": b"MM\x00\x2a",
    "ICO": b"\x00\x00\x01\x00",
    "DDS": b"DDS ",
    "KTX": b"\xabKTX 11\xbb\r\n\x1a\n",
    "KTX2": b"\xabKTX 20\xbb\r\n\x1a\n",
    "FLAC": b"fLaC",
    "Ogg": b"OggS",
    "MP3 ID3": b"ID3",
    "MIDI": b"MThd",
    "AU": b".snd",
    "Matroska/WebM": b"\x1a\x45\xdf\xa3",
    "QuickTime atom": b"moov",
    "ZIP": b"PK\x03\x04",
    "GZIP": b"\x1f\x8b\x08",
    "7-Zip": b"7z\xbc\xaf\x27\x1c",
}

RIFF_TYPES = {b"WAVE": "WAV", b"AVI ": "AVI", b"WEBP": "WEBP"}

ISO_BRANDS = {
    b"M4A ": "M4A/M4B", b"M4B ": "M4A/M4B",
    b"isom": "MP4", b"iso2": "MP4", b"mp41": "MP4", b"mp42": "MP4", b"avc1": "MP4", b"dash": "MP4",
    b"qt  ": "QuickTime",
    b"heic": "HEIF/HEIC", b"heix": "HEIF/HEIC", b"hevc": "HEIF/HEIC", b"hevx": "HEIF/HEIC", b"mif1": "HEIF/HEIC",
    b"avif": "AVIF", b"avis": "AVIF",
}


def find_all(data: bytes, pattern: bytes):
    offset = 0
    while (offset := data.find(pattern, offset)) != -1:
        yield offset
        offset += 1


def detect_riff(data: bytes, offset: int):
    if offset + 12 > len(data):
        return None
    return RIFF_TYPES.get(data[offset + 8:offset + 12], "RIFF")


def detect_iso_bmff(data: bytes, offset: int):
    if offset < 0 or offset + 12 > len(data):
        return None
    brand = data[offset + 8:offset + 12]
    return ISO_BRANDS.get(brand, f"ISO-BMFF ({brand.decode('ascii', errors='replace')})")


def is_mp3_frame(data: bytes, offset: int):
    if offset + 4 > len(data):
        return False
    first, second, third, _ = data[offset:offset + 4]
    version, layer = (second >> 3) & 0x03, (second >> 1) & 0x03
    bitrate, sample_rate = (third >> 4) & 0x0F, (third >> 2) & 0x03
    return first == 0xFF and second & 0xE0 == 0xE0 and version != 1 and layer != 0 and bitrate not in (0, 15) and sample_rate != 3


def scan_data(data: bytes, base_address: int):
    for name, pattern in SIGNATURES.items():
        for offset in find_all(data, pattern):
            yield base_address + offset, name

    for offset in find_all(data, b"RIFF"):
        if name := detect_riff(data, offset):
            yield base_address + offset, name

    for ftyp_offset in find_all(data, b"ftyp"):
        offset = ftyp_offset - 4
        if name := detect_iso_bmff(data, offset):
            yield base_address + offset, name

    for offset in find_all(data, b"\xff"):
        if is_mp3_frame(data, offset):
            yield base_address + offset, "MPEG Audio frame"


def is_readable(mbi: MEMORY_BASIC_INFORMATION):
    protection = mbi.Protect & 0xFF
    return mbi.State == MEM_COMMIT and not mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) and protection in READABLE_PROTECTIONS


def read_region(process, address: int, size: int):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = ReadProcessMemory(process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read))
    return buffer.raw[:bytes_read.value] if success and bytes_read.value else None


def scan_process(pid: int):
    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not process:
        error = ctypes.get_last_error()
        raise OSError(error, f"No se pudo abrir el PID {pid}: {ctypes.FormatError(error)}")

    mbi, address = MEMORY_BASIC_INFORMATION(), 0
    scanned_regions = scanned_bytes = found_count = 0

    try:
        while VirtualQueryEx(process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            region_base, region_size = int(mbi.BaseAddress or 0), int(mbi.RegionSize)

            if is_readable(mbi):
                data = read_region(process, region_base, region_size)
                if data:
                    scanned_regions += 1
                    scanned_bytes += len(data)
                    for hit_address, name in scan_data(data, region_base):
                        found_count += 1
                        print(f"[{name:<20}] 0x{hit_address:016X}")

            next_address = region_base + region_size
            if next_address <= address:
                break
            address = next_address
    finally:
        CloseHandle(process)

    print(f"\nRegiones leidas: {scanned_regions:,}")
    print(f"Bytes analizados: {scanned_bytes:,}")
    print(f"Firmas encontradas: {found_count:,}")


def main():
    parser = argparse.ArgumentParser(description="Busca firmas multimedia en la memoria de un proceso de Windows.")
    parser.add_argument("pid", type=int, help="PID del proceso objetivo")
    args = parser.parse_args()

    if args.pid <= 0:
        parser.error("PID debe ser un entero positivo")

    try:
        scan_process(args.pid)
    except KeyboardInterrupt:
        print("\nEscaneo interrumpido.")
    except (OSError, MemoryError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()