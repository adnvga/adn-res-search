import argparse
import ctypes
import hashlib
import json
import sys
from ctypes import wintypes
from pathlib import Path


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
    "FLAC": b"fLaC",
    "Ogg": b"OggS",
    "MP3 ID3": b"ID3",
    "MIDI": b"MThd",
    "AU": b".snd",

    # Imagenes: "PNG": b"\x89PNG\r\n\x1a\n", "JPEG": b"\xff\xd8\xff",
    # "GIF87a": b"GIF87a", "GIF89a": b"GIF89a", "BMP": b"BM",
    # "TIFF little-endian": b"II\x2a\x00", "TIFF big-endian": b"MM\x00\x2a",
    # "ICO": b"\x00\x00\x01\x00", "DDS": b"DDS ",
    # "KTX": b"\xabKTX 11\xbb\r\n\x1a\n", "KTX2": b"\xabKTX 20\xbb\r\n\x1a\n",
    # Video: "Matroska/WebM": b"\x1a\x45\xdf\xa3", "QuickTime atom": b"moov",
    # Comprimidos: "ZIP": b"PK\x03\x04", "GZIP": b"\x1f\x8b\x08", "7-Zip": b"7z\xbc\xaf\x27\x1c",
}

RIFF_TYPES = {
    b"WAVE": "WAV",
    # Video/imagen: b"AVI ": "AVI", b"WEBP": "WEBP",
}

ISO_BRANDS = {
    b"M4A ": "M4A/M4B", b"M4B ": "M4A/M4B",
    # Video: b"isom": "MP4", b"iso2": "MP4", b"mp41": "MP4", b"mp42": "MP4",
    # b"avc1": "MP4", b"dash": "MP4", b"qt  ": "QuickTime",
    # Imagenes: b"heic": "HEIF/HEIC", b"heix": "HEIF/HEIC", b"hevc": "HEIF/HEIC",
    # b"hevx": "HEIF/HEIC", b"mif1": "HEIF/HEIC", b"avif": "AVIF", b"avis": "AVIF",
}

MPEG_BITRATES = {
    (3, 3): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    (3, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (3, 1): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (2, 3): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (2, 1): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
MPEG_SAMPLE_RATES = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}
MIN_MP3_FRAMES = 10


def find_all(data: bytes, pattern: bytes):
    offset = 0
    while (offset := data.find(pattern, offset)) != -1:
        yield offset
        offset += 1


def detect_riff(data: bytes, offset: int):
    if offset + 12 > len(data):
        return None
    return RIFF_TYPES.get(data[offset + 8:offset + 12])


def detect_iso_bmff(data: bytes, offset: int):
    if offset < 0 or offset + 12 > len(data):
        return None
    brand = data[offset + 8:offset + 12]
    return ISO_BRANDS.get(brand)


def mp3_frame_info(data: bytes, offset: int):
    if offset + 4 > len(data):
        return None
    first, second, third, fourth = data[offset:offset + 4]
    version, layer = (second >> 3) & 0x03, (second >> 1) & 0x03
    bitrate_index, sample_rate_index = (third >> 4) & 0x0F, (third >> 2) & 0x03
    if first != 0xFF or second & 0xE0 != 0xE0 or version == 1 or layer == 0:
        return None
    if bitrate_index in (0, 15) or sample_rate_index == 3 or fourth & 0x03 == 2:
        return None

    table_version = 3 if version == 3 else 2
    bitrate = MPEG_BITRATES[(table_version, layer)][bitrate_index]
    sample_rate = MPEG_SAMPLE_RATES[version][sample_rate_index]
    padding = (third >> 1) & 1
    frame_size = ((12 * bitrate * 1000 // sample_rate) + padding) * 4 if layer == 3 else (144 if layer == 2 or version == 3 else 72) * bitrate * 1000 // sample_rate + padding
    if frame_size < 24 or offset + frame_size > len(data):
        return None
    return frame_size, version, layer, bitrate, sample_rate, "mono" if fourth >> 6 == 3 else "stereo"


def mp3_stream_info(data: bytes, offset: int):
    start, frame_offset = offset, offset
    if data[offset:offset + 3] == b"ID3":
        if offset + 10 > len(data) or data[offset + 3] not in (2, 3, 4) or any(byte & 0x80 for byte in data[offset + 6:offset + 10]):
            return None
        tag_size = sum(byte << shift for byte, shift in zip(data[offset + 6:offset + 10], (21, 14, 7, 0)))
        frame_offset += 10 + tag_size + (10 if data[offset + 3] == 4 and data[offset + 5] & 0x10 else 0)

    first_info, frames, position = None, 0, frame_offset
    while info := mp3_frame_info(data, position):
        if first_info and (info[1], info[2], info[4]) != (first_info[1], first_info[2], first_info[4]):
            break
        first_info = first_info or info
        frames += 1
        position += info[0]

    if frames < MIN_MP3_FRAMES:
        return None
    if data[position:position + 3] == b"TAG" and position + 128 <= len(data):
        position += 128

    frame_size, version, layer, bitrate, sample_rate, channels = first_info
    samples_per_frame = 384 if layer == 3 else 1152 if layer == 2 or version == 3 else 576
    return {
        "start": start, "end": position, "frames": frames,
        "mpeg_version": {3: "1", 2: "2", 0: "2.5"}[version],
        "layer": {3: "I", 2: "II", 1: "III"}[layer],
        "bitrate_kbps": bitrate, "sample_rate_hz": sample_rate, "channels": channels,
        "duration_seconds": round(frames * samples_per_frame / sample_rate, 3),
    }


def find_mp3_streams(data: bytes):
    streams = []

    for offset in find_all(data, b"ID3"):
        if stream := mp3_stream_info(data, offset):
            if not streams or stream["start"] >= streams[-1]["end"]:
                streams.append(stream)

    offset = 0
    while (offset := data.find(b"\xff", offset)) != -1:
        tagged_stream = next((stream for stream in streams if stream["start"] <= offset < stream["end"]), None)
        if tagged_stream:
            offset = tagged_stream["end"]
            continue
        if stream := mp3_stream_info(data, offset):
            streams.append(stream)
            offset = stream["end"]
        else:
            offset += 1

    yield from sorted(streams, key=lambda stream: stream["start"])


def ogg_stream_info(data: bytes, offset: int):
    if offset + 27 > len(data) or data[offset:offset + 4] != b"OggS" or not data[offset + 5] & 0x02:
        return None

    serial, position, pages, codec, last_granule = data[offset + 14:offset + 18], offset, 0, "unknown", 0
    while position + 27 <= len(data) and data[position:position + 4] == b"OggS" and data[position + 4] == 0:
        if data[position + 14:position + 18] != serial:
            return None
        segment_count = data[position + 26]
        header_end = position + 27 + segment_count
        if header_end > len(data):
            return None
        page_end = header_end + sum(data[position + 27:header_end])
        if page_end > len(data):
            return None

        if pages == 0:
            packet = data[header_end:page_end]
            codec = "Opus" if packet.startswith(b"OpusHead") else "Vorbis" if packet.startswith(b"\x01vorbis") else "FLAC" if packet.startswith(b"\x7fFLAC") else "unknown"

        pages += 1
        last_granule = int.from_bytes(data[position + 6:position + 14], "little")
        if data[position + 5] & 0x04:
            info = {"start": offset, "end": page_end, "extension": "ogg", "pages": pages, "codec": codec}
            if codec == "Opus" and last_granule < 2**63:
                info["duration_seconds"] = round(last_granule / 48000, 3)
            return info
        position = page_end
    return None


def iso_audio_info(data: bytes, offset: int):
    allowed_boxes = {b"ftyp", b"free", b"skip", b"wide", b"mdat", b"moov", b"uuid", b"meta", b"junk"}
    position, boxes = offset, []

    while position + 8 <= len(data):
        size, box_type, header_size = int.from_bytes(data[position:position + 4], "big"), data[position + 4:position + 8], 8
        if size == 1:
            if position + 16 > len(data):
                break
            size, header_size = int.from_bytes(data[position + 8:position + 16], "big"), 16
        if size < header_size or box_type not in allowed_boxes or position + size > len(data):
            break
        boxes.append(box_type.decode("ascii"))
        position += size

    if not boxes or boxes[0] != "ftyp" or "moov" not in boxes or "mdat" not in boxes:
        return None
    return {"start": offset, "end": position, "extension": "m4a", "boxes": boxes}


def wav_info(data: bytes, offset: int):
    if offset + 12 > len(data):
        return None
    end = offset + 8 + int.from_bytes(data[offset + 4:offset + 8], "little")
    position, metadata, data_size = offset + 12, None, 0

    while position + 8 <= end <= len(data):
        chunk_type = data[position:position + 4]
        chunk_size = int.from_bytes(data[position + 4:position + 8], "little")
        chunk_start, chunk_end = position + 8, position + 8 + chunk_size
        if chunk_end > end:
            return None
        if chunk_type == b"fmt " and chunk_size >= 16:
            metadata = {
                "encoding": int.from_bytes(data[chunk_start:chunk_start + 2], "little"),
                "channels": int.from_bytes(data[chunk_start + 2:chunk_start + 4], "little"),
                "sample_rate_hz": int.from_bytes(data[chunk_start + 4:chunk_start + 8], "little"),
                "byte_rate": int.from_bytes(data[chunk_start + 8:chunk_start + 12], "little"),
                "bits_per_sample": int.from_bytes(data[chunk_start + 14:chunk_start + 16], "little"),
            }
        elif chunk_type == b"data":
            data_size = chunk_size
        position = chunk_end + (chunk_size & 1)

    if not metadata or not data_size or not metadata["channels"] or not metadata["sample_rate_hz"] or not metadata["byte_rate"]:
        return None
    metadata["duration_seconds"] = round(data_size / metadata["byte_rate"], 3)
    return {"start": offset, "end": end, "extension": "wav", **metadata}


def audio_resource_info(data: bytes, offset: int, name: str):
    if name == "MP3":
        info = mp3_stream_info(data, offset)
        if info:
            info["extension"] = "mp3"
        return info

    if name == "WAV":
        return wav_info(data, offset)

    if name == "Ogg":
        return ogg_stream_info(data, offset)

    if name == "MIDI" and offset + 14 <= len(data):
        header_size = int.from_bytes(data[offset + 4:offset + 8], "big")
        midi_format = int.from_bytes(data[offset + 8:offset + 10], "big")
        tracks = int.from_bytes(data[offset + 10:offset + 12], "big")
        division = int.from_bytes(data[offset + 12:offset + 14], "big")
        if header_size < 6 or midi_format > 2 or not tracks or not division:
            return None
        position = offset + 8 + header_size
        for _ in range(tracks):
            if position + 8 > len(data) or data[position:position + 4] != b"MTrk":
                return None
            track_end = position + 8 + int.from_bytes(data[position + 4:position + 8], "big")
            if track_end > len(data) or not data[position + 8:track_end].endswith(b"\xff\x2f\x00"):
                return None
            position = track_end
        return {"start": offset, "end": position, "extension": "mid", "format": midi_format, "tracks": tracks, "division": division}

    if name == "AU" and offset + 24 <= len(data):
        data_offset = int.from_bytes(data[offset + 4:offset + 8], "big")
        data_size = int.from_bytes(data[offset + 8:offset + 12], "big")
        encoding = int.from_bytes(data[offset + 12:offset + 16], "big")
        sample_rate = int.from_bytes(data[offset + 16:offset + 20], "big")
        channels = int.from_bytes(data[offset + 20:offset + 24], "big")
        end = offset + data_offset + data_size
        if data_offset >= 24 and 0 < data_size != 0xFFFFFFFF and 1 <= encoding <= 27 and sample_rate and 1 <= channels <= 32 and end <= len(data):
            return {
                "start": offset, "end": end, "extension": "au",
                "encoding": encoding, "sample_rate_hz": sample_rate, "channels": channels,
            }

    if name == "M4A/M4B":
        return iso_audio_info(data, offset)
    return None


def scan_data(data: bytes, base_address: int):
    for name, pattern in SIGNATURES.items():
        if name == "MP3 ID3":
            continue
        for offset in find_all(data, pattern):
            yield base_address + offset, name

    for offset in find_all(data, b"RIFF"):
        if name := detect_riff(data, offset):
            yield base_address + offset, name

    for ftyp_offset in find_all(data, b"ftyp"):
        offset = ftyp_offset - 4
        if name := detect_iso_bmff(data, offset):
            yield base_address + offset, name

    for stream in find_mp3_streams(data):
        yield base_address + stream["start"], "MP3"


def is_readable(mbi: MEMORY_BASIC_INFORMATION):
    protection = mbi.Protect & 0xFF
    return mbi.State == MEM_COMMIT and not mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) and protection in READABLE_PROTECTIONS


def read_region(process, address: int, size: int):
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    success = ReadProcessMemory(process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read))
    return buffer.raw[:bytes_read.value] if success and bytes_read.value else None


def save_audio(output_dir: Path, data: bytes, base_address: int, name: str, resource: dict, known_files: dict):
    payload = data[resource["start"]:resource["end"]]
    digest = hashlib.sha256(payload).hexdigest()
    filename = known_files.get(digest, f"{digest[:16]}.{resource['extension']}")
    is_new = digest not in known_files

    if is_new:
        (output_dir / filename).write_bytes(payload)
        known_files[digest] = filename

    return {
        "address": f"0x{base_address + resource['start']:016X}",
        "format": name,
        "file": filename,
        "size_bytes": len(payload),
        "sha256": digest,
        "duplicate": not is_new,
        **{key: value for key, value in resource.items() if key not in ("start", "end", "extension")},
    }


def scan_process(pid: int):
    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not process:
        error = ctypes.get_last_error()
        raise OSError(error, f"No se pudo abrir el PID {pid}: {ctypes.FormatError(error)}")

    mbi, address = MEMORY_BASIC_INFORMATION(), 0
    scanned_regions = scanned_bytes = found_count = 0
    output_dir = Path("output") / str(pid)
    output_dir.mkdir(parents=True, exist_ok=True)
    known_files, recovered, candidate_counts = {}, [], {}

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
                        candidate_counts[name] = candidate_counts.get(name, 0) + 1
                        resource = audio_resource_info(data, hit_address - region_base, name)
                        if resource:
                            record = save_audio(output_dir, data, region_base, name, resource, known_files)
                            recovered.append(record)
                            if not record["duplicate"]:
                                print(f"[{name}] {record['address']} -> {output_dir / record['file']}")

            next_address = region_base + region_size
            if next_address <= address:
                break
            address = next_address
    finally:
        CloseHandle(process)

    manifest = {
        "pid": pid,
        "scanned_regions": scanned_regions,
        "scanned_bytes": scanned_bytes,
        "signatures_found": found_count,
        "candidate_counts": candidate_counts,
        "unique_audio_files": len(known_files),
        "audio_occurrences": recovered,
        "notes": [
            "Only resources with validated boundaries are written.",
            "FLAC signatures are counted but not written because the header does not declare the compressed stream size.",
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nRegiones leidas: {scanned_regions:,}")
    print(f"Bytes analizados: {scanned_bytes:,}")
    print(f"Firmas encontradas: {found_count:,}")
    print(f"Archivos de audio unicos: {len(known_files):,}")
    print(f"Manifiesto: {manifest_path}")


def main():
    parser = argparse.ArgumentParser(description="Busca y recupera audio desde la memoria de un proceso de Windows.")
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