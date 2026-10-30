import hashlib

BAD = {
    b"none", b"n/a", b"na", b"null", b"unknown", b"empty", b"0",
    b"to be filled by o.e.m.", b"to be filled by oem",
    b"default string", b"default", b"system serial number",
    b"not specified", b"not available", b"no serial",
    b"00000000", b"123456789", b"1234567890",
    b"oem", b"o.e.m", b"system manufacturer",
    b"system product name", b"base board serial number",
}

def cstr(value):
    return value.split(b"\0", 1)[0]

def trim(value):
    return cstr(value).strip(b" \t\r\n\v\f")

def serial(value):
    value = trim(value)
    return b"" if not value or value.lower() in BAD else value

def temporal_hwid(
    *,
    uuid_raw=None,
    system=b"",
    board=b"",
    disk=b"",
    vendor=b"",
    cpu_eax=0,
    brand=b"",
    sid=b"",
    hash_ok=True,
):
    uuid = b""
    if uuid_raw is not None:
        if len(uuid_raw) != 16:
            raise ValueError("uuid_raw must contain 16 raw SMBIOS bytes")
        if uuid_raw not in (bytes(16), b"\xff" * 16):
            uuid = uuid_raw.hex().encode("ascii")

    system = serial(system)
    board = serial(board)
    disk = serial(disk)

    if not (uuid or system or board or disk):
        return cstr(sid) or b"none"

    cpu = (
        cstr(vendor)
        + b"|"
        + f"{cpu_eax & 0xffffffff:08x}".encode("ascii")
        + b"|"
        + trim(brand)
    )

    record = (
        b"TemporalHWID|v1\0"
        + b"|uuid=" + uuid
        + b"|sys=" + system
        + b"|board=" + board
        + b"|cpu=" + cpu
        + b"|disk=" + disk
    )

    if not hash_ok:
        return record

    return hashlib.sha256(record).hexdigest().encode("ascii")
    
import ctypes as ct
from ctypes import wintypes as wt
import os
import platform
import struct

if (
    os.name != "nt"
    or ct.sizeof(ct.c_void_p) != 8
    or platform.machine().lower() not in ("amd64", "x86_64")
):
    raise RuntimeError("64-bit Python on x64 Windows is required")

kernel = ct.WinDLL("kernel32", use_last_error=True)
advapi = ct.WinDLL("advapi32", use_last_error=True)

ptr = ct.c_void_p
dword = wt.DWORD
handle = wt.HANDLE
pdword = ct.POINTER(dword)


def bind(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype = result
    fn.argtypes = list(args)
    return fn


firmware = bind(
    kernel, "GetSystemFirmwareTable",
    ct.c_uint, ct.c_uint, ct.c_uint, ptr, ct.c_uint
)
create_file = bind(
    kernel, "CreateFileW",
    handle, wt.LPCWSTR, dword, dword, ptr, dword, dword, handle
)
ioctl = bind(
    kernel, "DeviceIoControl",
    wt.BOOL, handle, dword, ptr, dword, ptr, dword, pdword, ptr
)
close_handle = bind(kernel, "CloseHandle", wt.BOOL, handle)
current_process = bind(kernel, "GetCurrentProcess", handle)
local_free = bind(kernel, "LocalFree", ptr, ptr)

open_token = bind(
    advapi, "OpenProcessToken",
    wt.BOOL, handle, dword, ct.POINTER(handle)
)
token_info = bind(
    advapi, "GetTokenInformation",
    wt.BOOL, handle, dword, ptr, dword, pdword
)
sid_string = bind(
    advapi, "ConvertSidToStringSidA",
    wt.BOOL, ptr, ct.POINTER(ptr)
)

alloc = bind(
    kernel, "VirtualAlloc",
    ptr, ptr, ct.c_size_t, dword, dword
)
protect = bind(
    kernel, "VirtualProtect",
    wt.BOOL, ptr, ct.c_size_t, dword, pdword
)
free_memory = bind(
    kernel, "VirtualFree",
    wt.BOOL, ptr, ct.c_size_t, dword
)
flush = bind(
    kernel, "FlushInstructionCache",
    wt.BOOL, handle, ptr, ct.c_size_t
)


def get_cpu():
    code = bytes.fromhex(
        "53 "
        "8b c1 "
        "8b ca "
        "0f a2 "
        "41 89 00 "
        "41 89 58 04 "
        "41 89 48 08 "
        "41 89 50 0c "
        "5b c3"
    )

    address = alloc(None, len(code), 0x3000, 0x04)
    if not address:
        raise ct.WinError(ct.get_last_error())

    try:
        ct.memmove(address, code, len(code))
        old = dword()
        if not protect(address, len(code), 0x20, ct.byref(old)):
            raise ct.WinError(ct.get_last_error())
        if not flush(current_process(), address, len(code)):
            raise ct.WinError(ct.get_last_error())

        native_cpuid = ct.WINFUNCTYPE(
            None, dword, dword, pdword
        )(address)

        def cpuid(leaf):
            out = (dword * 4)()
            native_cpuid(leaf, 0, out)
            return tuple(out)

        _, ebx, ecx, edx = cpuid(0)
        vendor = struct.pack("<III", ebx, edx, ecx)
        cpu_eax = cpuid(1)[0]

        brand = b""
        if cpuid(0x80000000)[0] >= 0x80000004:
            brand = b"".join(
                struct.pack("<4I", *cpuid(leaf))
                for leaf in range(0x80000002, 0x80000005)
            )

        return vendor, cpu_eax, brand
    finally:
        free_memory(address, 0, 0x8000)


def parse_smbios(raw):
    uuid_raw, system, board = None, b"", b""

    if len(raw) < 12:
        return uuid_raw, system, board

    size = struct.unpack_from("<I", raw, 4)[0]
    if not size or size > len(raw) - 8:
        return uuid_raw, system, board

    data = raw[8:8 + size]
    pos = 0

    while pos + 4 <= len(data):
        kind, length = data[pos], data[pos + 1]

        if kind == 127 or length < 4 or pos + length > len(data):
            break

        end = pos + length
        stop = data.find(b"\0\0", end)
        if stop < 0:
            break

        strings = data[end:stop].split(b"\0")

        def field(index):
            if 0 < index <= len(strings):
                return strings[index - 1]
            return b""

        if kind == 1 and length >= 25:
            value = data[pos + 8:pos + 24]
            if value not in (bytes(16), b"\xff" * 16):
                uuid_raw = value

            value = serial(field(data[pos + 7]))
            if value:
                system = value

        elif kind == 2 and length >= 8:
            value = serial(field(data[pos + 7]))
            if value:
                board = value

        pos = stop + 2

    return uuid_raw, system, board


def get_smbios():
    size = firmware(0x52534D42, 0, None, 0)
    if size < 12:
        return None, b"", b""

    buf = ct.create_string_buffer(size)
    if firmware(0x52534D42, 0, buf, size) != size:
        return None, b"", b""

    return parse_smbios(buf.raw)


def get_disk():
    device = create_file(
        r"\\.\PhysicalDrive0", 0, 3, None, 3, 0, None
    )
    if device is None or device == ptr(-1).value:
        return b""

    try:
        query = ct.create_string_buffer(12)
        output = ct.create_string_buffer(1024)
        returned = dword()

        if not ioctl(
            device, 0x2D1400,
            query, 12,
            output, 1024,
            ct.byref(returned), None
        ):
            return b""

        if returned.value < 40:
            return b""

        offset = struct.unpack_from("<I", output.raw, 24)[0]
        if not offset or offset >= returned.value or offset >= 1024:
            return b""

        return serial(output.raw[offset:])
    finally:
        close_handle(device)


def get_sid():
    token = handle()
    if not open_token(current_process(), 8, ct.byref(token)):
        return b""

    try:
        needed = dword()
        token_info(token, 1, None, 0, ct.byref(needed))
        if not needed.value:
            return b""

        buf = ct.create_string_buffer(needed.value)
        if not token_info(
            token, 1, buf, needed.value, ct.byref(needed)
        ):
            return b""

        sid = ptr.from_buffer(buf).value
        text = ptr()

        if not sid_string(sid, ct.byref(text)) or not text.value:
            return b""

        try:
            return ct.string_at(text.value)
        finally:
            local_free(text.value)
    finally:
        close_handle(token)


def collect_values():
    uuid_raw, system, board = get_smbios()
    vendor, cpu_eax, brand = get_cpu()
    disk = get_disk()

    sid = b""
    if not (uuid_raw or system or board or disk):
        sid = get_sid()

    return {
        "uuid_raw": uuid_raw,
        "system": system,
        "board": board,
        "disk": disk,
        "vendor": vendor,
        "cpu_eax": cpu_eax,
        "brand": brand,
        "sid": sid,
    }


if __name__ == "__main__":
    values = collect_values()
    result = temporal_hwid(**values)
    print(result.decode("ascii"))