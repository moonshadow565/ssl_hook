static_assert(sizeof(void*) == 4, "Compile in 32bit mode");
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <charconv>
#include "MinHook.h"
#include "ppp.hpp"
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#define assert(what) do { if (!(what)) { logger.log_fail(#what); exit(1); } } while(false)

constexpr auto find_SSL_set_fd = &ppp::any<
    R"(o[56] 8B 74 24 08 57 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 04 85 FF)"_pattern,
    R"(o[56] 8B EC 57 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 04 85 FF 75 20 68 57 05 00 00)"_pattern,
    R"(E8 r[?? ?? ?? ??] 6A 00 6A 05 6A 21)"_pattern
    >;

constexpr auto find_ssl_read_internal = &ppp::any<
    R"(o[B8] 14 00 00 00 E8 ?? ?? ?? ?? 56 8B 74 24 1C 83 7E 18 00 75 26 68 C9 06 00 00)"_pattern,
    R"(o[55] 8B EC B8 14 00 00 00 E8 ?? ?? ?? ?? 56 8B 75 08 83 BE B0 06 00 00 00 74 23 68 D0 06 00 00)"_pattern
    >;
constexpr auto find_ssl_write_internal = &ppp::any<
    R"(o[B8] 14 00 00 00 E8 ?? ?? ?? ?? 56 8B 74 24 1C 83 7E 18 00 75 26 68 89 07 00 00)"_pattern,
    R"(o[55] 8B EC B8 14 00 00 00 E8 ?? ?? ?? ?? 56 8B 75 08 83 BE B0 06 00 00 00 74 23 68 9C 07 00 00)"_pattern
    >;

struct Offsets {
    std::uint32_t SSL_set_fd = 0;
    std::uint32_t ssl_read_internal = 0;
    std::uint32_t ssl_write_internal = 0;
    
    Offsets() noexcept = default;
    
    Offsets(std::uintptr_t base) noexcept {
        auto const dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        auto const nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        auto const size = nt->OptionalHeader.SizeOfImage;
        auto data = std::vector<char>(size);
        for (auto offset = DWORD{}; offset < size; offset += 0x1000) {
            ReadProcessMemory(GetCurrentProcess(),
                              (LPCVOID)(base + offset),
                              data.data() + offset,
                              std::min(size - offset, DWORD{0x1000}),
                              nullptr);
        }
        if (auto const found = find_SSL_set_fd(data, 0)) {
            SSL_set_fd = (std::uint32_t)std::get<1>(*found);
        }
        if (auto const found = find_ssl_read_internal(data, 0)) {
            ssl_read_internal = (std::uint32_t)std::get<1>(*found);
        }
        if (auto const found = find_ssl_write_internal(data, 0)) {
            ssl_write_internal = (std::uint32_t)std::get<1>(*found);
        }
//        if (auto file = fopen("./ssl_logs/dump.exe", "wb+")) {
//            fwrite(data.data(), 1, data.size(), file);
//            fclose(file);
//        }
    }
};


struct Logger {
private:
    std::chrono::steady_clock clock = {};
    FILE* file = {};
    std::mutex mutex = {};

    int64_t time() const noexcept {
        auto epoch = clock.now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    }

    template<auto FUNC, size_t S>
    void log_fd_impl(char const(&name)[S], void const* s, int fd, unsigned long long t) noexcept {
        union address_t {
            sockaddr addr;
            sockaddr_in addr4;
        } addr;
        int addrlen;
        memset(&addr, 0, sizeof(addr));
        addrlen = sizeof(addr);
        if (FUNC(fd, &addr.addr, &addrlen) != 0 || addrlen < sizeof(sockaddr_in)) {
            return;
        }
        auto [ip0, ip1, ip2, ip3] = addr.addr4.sin_addr.S_un.S_un_b;
        auto port = addr.addr4.sin_port;
        auto family = addr.addr4.sin_family;
        fprintf(file, "%s: 0x%p, address: %u.%u.%u.%u, port: %u, familiy: %u\n", name, s, ip0, ip1, ip2, ip3, port, family);
    }
public:
    ~Logger() noexcept {
        fprintf(file, "end\n");
        fflush(file);
        fclose(file);
    }

    void log_module(char const* moduleName, uintptr_t base) noexcept {
        fprintf(file, "module: %s, base: 0x%p\n", moduleName ? moduleName : "nullptr", (void*)base);
    }

    void log_fail(char const* desc) noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        fprintf(file, "fail: %s\n", desc);
        fflush(file);
    }

    void log_read(void const* s, void const* data, size_t num, size_t size) noexcept {
        unsigned long long t = time();
        std::lock_guard<std::mutex> lock(mutex);
        fprintf(file, "read: 0x%p, time: %llu, req: 0x%X, got: 0x%X\n", s, t, (uint32_t)num, (uint32_t)size);
        fwrite(data, 1, size, file);
        fwrite("\n", 1, 1, file);
        fflush(file);
    }

    void log_write(void const* s, void const* data, size_t num, size_t size) noexcept {
        unsigned long long t = time();
        std::lock_guard<std::mutex> lock(mutex);
        fprintf(file, "write: 0x%p, time: %llu, req: 0x%X, got: 0x%X\n", s, t, (uint32_t)num, (uint32_t)size);
        fwrite(data, 1, size, file);
        fwrite("\n", 1, 1, file);
        fflush(file);
    }


    void log_fd(void const* s, int fd) noexcept {
        unsigned long long t = time();
        std::lock_guard<std::mutex> lock(mutex);
        log_fd_impl<&getpeername>("fd_peer", s, fd, t);
        log_fd_impl<&getsockname>("fd_sock", s, fd, t);
        fflush(file);
    }

    bool open_folder(std::filesystem::path folder) noexcept {
        namespace fs = std::filesystem;
        std::error_code ec = {};
        fs::create_directories(folder, ec);
        auto timestamp = std::chrono::seconds(std::time(nullptr)).count();
        auto filename = folder / ("log_" + std::to_string(timestamp) + ".txt");
        file = fopen(filename.string().c_str(), "wb");
        setbuf(file, nullptr);
        return !!file;
    }
} logger = {};

template<size_t ID>
struct Hook {
    inline static int (*ssl_read_internal_org)(void* s, void* buf, size_t num, size_t* readbytes) = nullptr;
    static int ssl_read_internal_hook(void* s, void* buf, size_t num, size_t* readbytes) {
        int result = ssl_read_internal_org(s, buf, num, readbytes);
        if (result > 0 && *readbytes) {
            logger.log_read(s, buf, num, *readbytes);
        }
        return result;
    }
    
    inline static int (*ssl_write_internal_org)(void* s, void const* buf, size_t num, size_t* written) = nullptr;
    static int ssl_write_internal_hook(void* s, void const* buf, size_t num, size_t* written) {
        int result = ssl_write_internal_org(s, buf, num, written);
        if (result > 0 && *written) {
            logger.log_write(s, buf, num, *written);
        }
        return result;
    }
    
    inline static int (*SSL_set_fd_org)(void* s, int fd) = nullptr;
    static int SSL_set_fd_hook(void* s, int fd) {
        int result = SSL_set_fd_org(s, fd);
        if (result == 1) {
            logger.log_fd(s, fd);
        }
        return result;
    }

    template<typename T>
    static bool hook_fn(uintptr_t addr, T* hook, T*& org) noexcept {
        if (MH_CreateHook((void*)(addr), (void*)hook, (void**)&org) != MH_OK) {
            return false;
        }
        if (MH_EnableHook((void*)(addr)) != MH_OK) {
            return false;
        }
        return true;
    }

    static bool hook_module(char const* moduleName) {
        auto const base = (uintptr_t)GetModuleHandleA(moduleName);
        if (!base) {
            return false;
        }
        logger.log_module(moduleName, base);
        auto offsets = Offsets(base);
        assert(offsets.SSL_set_fd);
        assert(offsets.ssl_read_internal);
        assert(offsets.ssl_write_internal);
        assert(hook_fn(base + offsets.ssl_read_internal, &ssl_read_internal_hook, ssl_read_internal_org));
        assert(hook_fn(base + offsets.ssl_write_internal, &ssl_write_internal_hook, ssl_write_internal_org));
        assert(hook_fn(base + offsets.SSL_set_fd, &SSL_set_fd_hook, SSL_set_fd_org));
        assert(MH_ApplyQueued() == MH_OK);
        return true;
    }

    static void hook_module_wait(char const* moduleName, uint32_t interval, uint32_t timeout) {
        auto thread = std::thread([=] {
            uint32_t elapsed = 0;
            while (!hook_module(moduleName)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(interval));
                elapsed += interval;
                if (timeout == 0 || elapsed >= timeout) {
                    break;
                }
            }
        });
        thread.detach();
    }
};

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    if (!logger.open_folder("./ssl_logs")) {
        exit(1);
    }
    assert(MH_Initialize() == MH_OK);
    Hook<0>::hook_module(nullptr);
    // Hook<1>::hook_module_wait("RiotClientFoundation.dll", 50, 30000);
    return TRUE;
}
