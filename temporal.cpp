#include <windows.h>
#include <stdint.h>
#include <tlhelp32.h>

#pragma pack(push, 1)
struct GetBaseRequest {
    uint32_t auth;
    uint32_t pid;
    uint64_t* result;
};

struct ReadWriteRequest {
    uint32_t auth;
    uint32_t pid;
    uint64_t address;
    uint64_t buffer;
    uint64_t size;
    uint8_t  direction;
    uint8_t  pad[7];
};
#pragma pack(pop)

class TemporalDriver {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    uint32_t targetPid = 0;

public:
    bool Connect() {
        const wchar_t* paths[] = {
            L"\\\\.\\Global\\WdfPortA81",
            L"\\\\.\\WdfPortA81",
            L"\\\\.\\GLOBALROOT\\GLOBAL??\\WdfPortA81",
        };
        for (int attempt = 0; attempt < 10; attempt++) {
            for (auto path : paths) {
                hDevice = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (hDevice != INVALID_HANDLE_VALUE)
                    return true;
            }
            Sleep(50);
        }
        return false;
    }

    void Disconnect() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            hDevice = INVALID_HANDLE_VALUE;
        }
    }

    void SetPid(uint32_t pid) { targetPid = pid; }

    uint64_t GetModuleBase(uint32_t pid) {
        uint64_t result = 0;
        GetBaseRequest req{};
        req.auth = 0x19C4F2A6 ^ 0x5B07D3E1;
        req.pid = pid;
        req.result = &result;
        DWORD ret;
        DeviceIoControl(hDevice, 0x229ACC, &req, sizeof(req), nullptr, 0, &ret, nullptr);
        return result;
    }

    bool Read(uint64_t address, void* buffer, size_t size) {
        for (size_t off = 0; off < size; ) {
            uint32_t chunk = min((uint32_t)(size - off), 0x1000u - ((uint32_t)(address + off) & 0xFFF));
            ReadWriteRequest req{};
            req.auth = 0x19C4F2A6 ^ 0x5B07D3E1;
            req.pid = targetPid;
            req.address = address + off;
            req.buffer = (uint64_t)((uint8_t*)buffer + off);
            req.size = chunk;
            req.direction = 0;
            DWORD ret;
            if (!DeviceIoControl(hDevice, 0x2347A0, &req, sizeof(req), nullptr, 0, &ret, nullptr))
                return false;
            off += chunk;
        }
        return true;
    }

    bool Write(uint64_t address, void* buffer, size_t size) {
        for (size_t off = 0; off < size; ) {
            uint32_t chunk = min((uint32_t)(size - off), 0x1000u - ((uint32_t)(address + off) & 0xFFF));
            ReadWriteRequest req{};
            req.auth = 0x19C4F2A6 ^ 0x5B07D3E1;
            req.pid = targetPid;
            req.address = address + off;
            req.buffer = (uint64_t)((uint8_t*)buffer + off);
            req.size = chunk;
            req.direction = 1;
            DWORD ret;
            if (!DeviceIoControl(hDevice, 0x2347A0, &req, sizeof(req), nullptr, 0, &ret, nullptr))
                return false;
            off += chunk;
        }
        return true;
    }

    template<typename T>
    T Read(uint64_t address) {
        T val{};
        Read(address, &val, sizeof(T));
        return val;
    }

    template<typename T>
    bool Write(uint64_t address, T value) {
        return Write(address, &value, sizeof(T));
    }

    static uint32_t FindProcess(const wchar_t* name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32W pe{ sizeof(pe) };
        uint32_t pid = 0;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, name) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return pid;
    }
};
