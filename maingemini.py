import sys
import ctypes
from ctypes import wintypes

# --- Estructuras y Constantes de la API de Windows ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# Cargar DLLs nativas de Windows
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

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


# --- Firmas de Archivos Multimedia (Magic Bytes) ---
MAGIC_BYTES = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "BMP": b"BM",
    "WEBP": b"RIFF",  # Las cabeceras WebP inician con RIFF...WEBP
    "WAV": b"RIFF",   # WAV también usa contenedor RIFF (requiere verificación posterior)
    "MP3 (ID3v2)": b"ID3",
    "FLAC": b"fLaC",
    "OGG": b"OggS",
}


def scan_process_memory(pid: int):
    # Intentar abrir el proceso objetivo
    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        print(f"[-] No se pudo abrir el proceso {pid}. Asegúrate de ejecutar la consola como Administrador.")
        return

    print(f"[+] Escaneando memoria del PID: {pid}...\n")
    
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    
    found_count = 0

    # Recorrer el espacio de direcciones del proceso
    while VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size):
        # Filtrar páginas comprometidas y legibles (omitir guard pages y sin acceso)
        is_accessible = (
            (mbi.State == MEM_COMMIT) and 
            not (mbi.Protect & PAGE_NOACCESS) and 
            not (mbi.Protect & PAGE_GUARD)
        )

        if is_accessible:
            buffer = ctypes.create_string_buffer(mbi.RegionSize)
            bytes_read = ctypes.c_size_t(0)

            # Leer la región de memoria actual
            if ReadProcessMemory(h_process, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                raw_data = buffer.raw[:bytes_read.value]

                # Buscar cada tipo de Magic Byte dentro de la región
                for fmt_name, signature in MAGIC_BYTES.items():
                    offset = raw_data.find(signature)
                    while offset != -1:
                        match_address = mbi.BaseAddress + offset
                        
                        # Verificación extra para contenedores RIFF (Diferenciar WAV y WEBP)
                        extra_info = ""
                        if signature == b"RIFF" and (offset + 12 <= len(raw_data)):
                            sub_type = raw_data[offset + 8 : offset + 12]
                            extra_info = f" (Subtipo: {sub_type.decode('ascii', errors='ignore')})"

                        print(f"  [>] Firma encontrada: {fmt_name:<12}{extra_info} | Dirección: 0x{match_address:016X}")
                        found_count += 1
                        
                        # Continuar buscando más coincidencias en la misma región
                        offset = raw_data.find(signature, offset + 1)

        # Avanzar a la siguiente región de memoria
        address = mbi.BaseAddress + mbi.RegionSize

    CloseHandle(h_process)
    print(f"\n[+] Escaneo finalizado. Total de coincidencias: {found_count}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python main.py <PID>")
        sys.exit(1)

    try:
        target_pid = int(sys.argv[1])
        scan_process_memory(target_pid)
    except ValueError:
        print("Error: El PID debe ser un número entero.")
        sys.exit(1)