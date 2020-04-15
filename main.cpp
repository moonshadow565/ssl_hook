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
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#define assert(what) do { if (!(what)) { logger.log_fail(#what); exit(1); } } while(false)

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
        fprintf(file, "module: %s, base: 0x%p\n", moduleName ? moduleName : "nullptr", base);
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
    }

    void log_write(void const* s, void const* data, size_t num, size_t size) noexcept {
        unsigned long long t = time();
        std::lock_guard<std::mutex> lock(mutex);
        fprintf(file, "write: 0x%p, time: %llu, req: 0x%X, got: 0x%X\n", s, t, (uint32_t)num, (uint32_t)size);
        fwrite(data, 1, size, file);
        fwrite("\n", 1, 1, file);
    }


    void log_fd(void const* s, int fd) noexcept {
        unsigned long long t = time();
        std::lock_guard<std::mutex> lock(mutex);
        log_fd_impl<&getpeername>("fd_peer", s, fd, t);
        log_fd_impl<&getsockname>("fd_sock", s, fd, t);
    }

    bool open_folder(std::filesystem::path folder) noexcept {
        namespace fs = std::filesystem;
        auto filename = folder / "log_redirect.txt";
        if (fs::exists(filename) && fs::is_symlink(filename)) {
            std::error_code ec = {};
            filename = fs::read_symlink(filename, ec);
        }
        if (!fs::exists(filename) || !fs::is_fifo(filename) || !fs::is_socket(filename)) {
            std::error_code ec = {};
            fs::create_directories(folder, ec);
            auto timestamp = std::chrono::seconds(std::time(nullptr)).count();
            filename = folder / ("log_" + std::to_string(timestamp) + ".txt");
        }
        file = fopen(filename.string().c_str(), "wb");
        return !!file;
    }
};

static Logger logger = {};

struct Config {
    uintptr_t read = 0;
    uintptr_t write = 0;
    uintptr_t set_fd = 0;
    uintptr_t checksum = 0;

    void load(std::filesystem::path const& folder, uintptr_t new_checksum) noexcept {
        auto filename = (folder / ("config_" + std::to_string(new_checksum) + ".cfg")).string();
        auto file = fopen(filename.c_str(), "rb");
        if (!file) {
            return;
        }
        fscanf(file, "v1 %p %p %p %p\n", (void**)&read, (void**)&write, (void**)&set_fd, (void**)&checksum);
        fclose(file);
        if (new_checksum != checksum) {
            *this = {};
        }
    }

    void save(std::filesystem::path const& folder) const noexcept {
        auto filename = (folder / ("config_" + std::to_string(checksum) + ".cfg")).string();
        auto file = fopen(filename.c_str(), "wb");
        if (!file) {
            return;
        }
        fprintf(file, "v1 %p %p %p %p\n", (void*)read, (void*)write, (void*)set_fd, (void*)checksum);
        fclose(file);
    }

    bool valid() const noexcept {
        return checksum && read && write && set_fd;
    }
};

inline constexpr uint16_t Any = 0x0100u;
inline constexpr uint16_t Cap = 0x0200u;
template <uint16_t... ops>
inline auto Search(std::vector<uint8_t> const& data) noexcept {
    return [](uint8_t const* start, size_t size) constexpr noexcept {
        std::array<uint8_t const*, ((ops& Cap ? 1 : 0) + ... + 1)> result = {};
        uint8_t const* const end = start + size + sizeof...(ops);
        for (uint8_t const* i = start; i != end; i++) {
            uint8_t const* c = i;
            if (((*c++ == (ops & 0xFF) || (ops & Any)) && ...)) {
                uint8_t const* o = i;
                size_t r = 0;
                result[r++] = o;
                ((ops & Cap ? result[r++] = o++ : o++), ...);
                return result;
            }
        }
        return result;
    } (data.data(), data.size());
}

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

    static bool hook_module(std::filesystem::path const& folder, char const* moduleName) {
        auto const base = (uintptr_t)GetModuleHandleA(moduleName);
        if (!base) {
            return false;
        }
        logger.log_module(moduleName, base);
        auto const handle = GetCurrentProcess();
        auto checksum = uintptr_t{ 0 };
        auto size = size_t{ 0 };
        {
            char raw[1024] = {};
            assert(ReadProcessMemory(handle, (void const*)base, raw, sizeof(raw), nullptr));
            auto const dos = (PIMAGE_DOS_HEADER)(raw);
            assert(dos->e_magic == IMAGE_DOS_SIGNATURE);
            auto const nt = (PIMAGE_NT_HEADERS32)(raw + dos->e_lfanew);
            assert(nt->Signature == IMAGE_NT_SIGNATURE);
            checksum = (uint32_t)(nt->OptionalHeader.CheckSum);
            size = (size_t)(nt->OptionalHeader.SizeOfImage);
        }
        assert(checksum);
        auto config = Config{};
        config.load(folder, checksum);
        if (!config.valid()) {
            auto data = std::vector<uint8_t>(size);
            for (size_t i = 0; i < size; i += 0x1000) {
                ReadProcessMemory(handle, (void const*)(base + i), data.data() + i, 0x1000, nullptr);
            }
            auto search_ssl_read = Search< //
                0x55,
                0x8B, 0xEC,
                0xB8, 0x14, 0x00, 0x00, 0x00,
                0xE8, Any, Any, Any, Any,
                0x56,
                0x8B, 0x75, 0x08,
                0x83, 0xBE, 0xA8, 0x06, 0x00, 0x00, 0x00,
                0x74, 0x23,
                0x68, Any, Any, Any, Any,
                0x68, Any, Any, Any, Any,
                0x6A, 0x42,
                0x68, 0x0B, 0x02, 0x00, 0x00,
                0x6A, 0x14
            >(data);
            assert(search_ssl_read[0]);
            config.read = (uintptr_t)(search_ssl_read[0] - data.data());
            auto search_ssl_write = Search< //
                0x55,
                0x8B, 0xEC,
                0xB8, 0x14, 0x00, 0x00, 0x00,
                0xE8, Any, Any, Any, Any,
                0x56,
                0x8B, 0x75, 0x08,
                0x83, 0xBE, 0xA8, 0x06, 0x00, 0x00, 0x00,
                0x74, 0x23,
                0x68, Any, Any, Any, Any,
                0x68, Any, Any, Any, Any,
                0x6A, 0x42,
                0x68, 0x0C, 0x02, 0x00, 0x00,
                0x6A, 0x14
            >(data);
            assert(search_ssl_write[0]);
            config.write = (uintptr_t)(search_ssl_write[0] - data.data());
            auto search_fd_set = Search< //
                0x55,
                0x8B, 0xEC,
                0x57,
                0xE8, Any, Any, Any, Any,
                0x50,
                0xE8, Any, Any, Any, Any,
                0x8B, 0xF8,
                0x83, 0xC4, 04,
                0x85, 0xFF,
                0x75, 0x20,
                0x68, Any, Any, Any, Any,
                0x68, Any, Any, Any, Any,
                0x6A, 0x07,
                0x68, 0xC0, 0x00, 0x00, 0x00,
                0x6A, 0x14
            >(data);
            assert(search_fd_set[0]);
            config.set_fd = (uintptr_t)(search_fd_set[0] - data.data());
            config.checksum = checksum;
            config.save(folder);
        }
        assert(config.valid());
        assert(hook_fn(base + config.read, &ssl_read_internal_hook, ssl_read_internal_org));
        assert(hook_fn(base + config.write, &ssl_write_internal_hook, ssl_write_internal_org));
        assert(hook_fn(base + config.set_fd, &SSL_set_fd_hook, SSL_set_fd_org));
        assert(MH_ApplyQueued() == MH_OK);
        return true;
    }

    static void hook_module_wait(std::filesystem::path const& folder, char const* moduleName,
                                 uint32_t interval, uint32_t timeout) {
        auto thread = std::thread([=] {
            uint32_t elapsed = 0;
            while (!hook_module(folder, moduleName)) {
                elapsed += interval;
                if (timeout == 0 || elapsed >= timeout) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(interval));
            }
        });
        thread.detach();
    }
};

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    auto folder = std::filesystem::path("./ssl_logs");
    if (!std::filesystem::exists(folder)) {
        std::error_code ec = {};
        std::filesystem::create_directories(folder, ec);
        if (ec != std::errc{}) {
            exit(1);
        }
    }
    if (!logger.open_folder(folder)) {
        exit(1);
    }
    assert(MH_Initialize() == MH_OK);
    Hook<0>::hook_module(folder, nullptr);
    Hook<1>::hook_module_wait(folder, "Foundation.dll", 50, 30000);
    return TRUE;
}
