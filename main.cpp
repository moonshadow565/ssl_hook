#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include "MinHook.h"
#ifndef NDEBUG
#error "Compile in release mode"
#endif
#ifdef WIN32
static_assert(sizeof(void*) == 4, "Compile in 32bit mode");
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#else
static_assert(sizeof(void*) == 8, "Compile in 64bit mode only!");
#error "implement GetBaseAddress for not WIN32"
#endif

struct Logger {
private:
    std::chrono::steady_clock clock = {};
    std::ofstream file = {};
    std::mutex lock = {};

    struct Message {
        char type[8] = {};      // type of message
        uint64_t sslid = {};    // id of ssl connection
        int64_t time = {};      // time in miliseconds
        uint32_t info = {};     // message specific number
        uint32_t size = {};     // size of data unpadded
        char data[];            // data padded to align 16 bytes
    };
    static_assert (sizeof(Message) == 32);

    int64_t time() const noexcept {
        auto epoch = clock.now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    }

    void send(Message const& message, void const* data) noexcept {
        std::lock_guard<std::mutex> guard{lock};
        file.write((char const*)&message, sizeof(Message));
        if (message.size) {
            file.write((char const*)data, (std::streamsize)message.size);
            if (auto remain = message.size % 16; remain) {
                char const pad[16] = {};
                file.write(pad, (std::streamsize)(16 - remain));
            }
        }
    }
public:
    ~Logger() noexcept {
        log_end();
    }

    void log_start() noexcept {
        send({"start", 0, time(), 0, 0 }, nullptr);
    }

    void log_end() noexcept {
        send({"start", 0, time(), 0, 0 }, nullptr);
    }

    void log_fail(char const* desc) noexcept {
        send({"fail", 0, time(), 0, (uint32_t)strlen(desc) }, desc);
    }

    void log_read(void const* s, void const* data, size_t num, size_t size) noexcept {
        send({"read",  (uintptr_t)s, time(), (uint32_t)num, (uint32_t)size}, data);
    }

    void log_write(void const* s, void const* data, size_t num, size_t size) noexcept {
        send({"write",  (uintptr_t)s, time(), (uint32_t)num, (uint32_t)size}, data);
    }

    void log_fd(void const* s, int fd) noexcept {
        auto t = time();
        union {
            sockaddr addr;
            sockaddr_in addr4;
        } addr;
        int addrlen;
        memset(&addr, 0, sizeof(addr));
        addrlen = sizeof(addr);
        if (getpeername(fd, &addr.addr, &addrlen) != 0) {
            send({"fd_peer",  (uintptr_t)s, t, (uint32_t)fd, 0}, nullptr);
        } else {
            send({"fd_peer",  (uintptr_t)s, t, (uint32_t)fd, (uint32_t)addrlen}, &addr);
        }
        memset(&addr, 0, sizeof(addr));
        addrlen = sizeof(addr);
        if (getsockname(fd, &addr.addr, &addrlen) != 0) {
            send({"fd_sock",  (uintptr_t)s, t, (uint32_t)fd, 0}, nullptr);
        } else {
            send({"fd_sock",  (uintptr_t)s, t, (uint32_t)fd, (uint32_t)addrlen}, &addr);
        }
    }

    bool open_folder(std::filesystem::path folder) noexcept {
        namespace fs = std::filesystem;
        auto filename = folder / "redirect.bin";
        if (fs::exists(filename) && fs::is_symlink(filename)) {
            std::error_code ec = {};
            filename = fs::read_symlink(filename, ec);
        }
        if (!fs::exists(filename) || !fs::is_fifo(filename) || !fs::is_socket(filename)) {
            std::error_code ec = {};
            fs::create_directories(folder, ec);
            auto timestamp = std::chrono::seconds(std::time(nullptr)).count();
            filename = folder / ("log_" + std::to_string(timestamp) + ".bin");
        }
        file.open(filename, std::ios::binary);
        return file.good();
    }
};

static Logger logger = {};
extern "C" {
    static int (*ssl_read_internal_org)(void* s, void* buf, size_t num, size_t *readbytes);
    static int ssl_read_internal_hook(void* s, void* buf, size_t num, size_t *readbytes) {
        int result = ssl_read_internal_org(s, buf, num, readbytes);
        if (result > 0 && *readbytes) {
            logger.log_read(s, buf, num, *readbytes);
        }
        return result;
    }
    static int (*ssl_write_internal_org)(void* s, void const* buf, size_t num, size_t *written);
    static int ssl_write_internal_hook(void* s, void const* buf, size_t num, size_t *written) {
        int result = ssl_write_internal_org(s, buf, num, written);
        if (result > 0 && *written) {
            logger.log_write(s, buf, num, *written);
        }
        return result;
    }
    static int (*SSL_set_fd_org)(void *s, int fd);
    static int SSL_set_fd_hook(void *s, int fd) {
        int result = SSL_set_fd_org(s, fd);
        if (result == 1) {
            logger.log_fd(s, fd);
        }
        return result;
    }
}

inline constexpr uint16_t Any = 0x0100u;
inline constexpr uint16_t Cap = 0x0200u;
template <uint16_t... ops>
inline auto Search( std::vector<uint8_t> const& data) noexcept {
    return [](uint8_t const *start, size_t size) constexpr noexcept {
        std::array<uint8_t const *, ((ops & Cap ? 1 : 0) + ... + 1)> result = {};
        uint8_t const *const end = start + size + sizeof...(ops);
        for (uint8_t const *i = start; i != end; i++) {
            uint8_t const *c = i;
            if (((*c++ == (ops & 0xFF) || (ops & Any)) && ...)) {
                uint8_t const *o = i;
                size_t r = 0;
                result[r++] = o;
                ((ops & Cap ? result[r++] = o++ : o++), ...);
                return result;
            }
        }
        return result;
    }(data.data(), data.size());
}

template<typename T>
static bool Hook(uintptr_t addr, T* hook, T*& org) noexcept {
    if (MH_CreateHook((void*)(addr), (void*)hook, (void**)&org) != MH_OK) {
        return false;
    }
    if (MH_QueueEnableHook((void*)(addr)) != MH_OK) {
        return false;
    }
    return true;
}

#ifdef WIN32
static uintptr_t GetBaseAddress() noexcept {
    return (uintptr_t)GetModuleHandleA(nullptr);
}

static std::vector<uint8_t> DumpData(uintptr_t base) noexcept {
    constexpr size_t capacity = 64 * 1024 * 1024; // 64MB is plenty
    constexpr size_t page_size = 0x1000;
    static_assert(capacity % page_size == 0);
    auto data = std::vector<uint8_t>{};
    data.resize(capacity);
    auto handle = GetCurrentProcess();
    for (size_t i = 0; i != capacity; i += page_size) {
        ReadProcessMemory(handle, (void const*)(base + i), &data[i], capacity, nullptr);
    }
    return data;
}

struct Init {
    Init() {
        if (!logger.open_folder("./ssl_logs")) {
            exit(1);
        }
        logger.log_start();
        auto base = GetBaseAddress();
        auto data = DumpData(base);
        MH_Initialize();
        if (auto const s = Search< // 0x6CDD50
                0xB8, 0x14, 0x00, 0x00, 0x00,   // mov     eax, 14h
                0xE8, Any, Any, Any, Any,       // call    j___alloca_probe
                0x56,                           // push    esi
                0x8B, 0x74, 0x24, 0x1C,         // mov     esi, [esp+18h+arg_0]
                0x83, 0x7E, 0x18, 0x00,         // cmp     dword ptr [esi+18h], 0
                0x75, 0x26,                     // jnz     $+5
                0x68, Any, Any, Any, Any,       // push    ????
                0x68, Any, Any, Any, Any,       // push    "ssl\\ssl_lib.c"
                0x68, 0x14, 0x01, 0x00, 0x00,   // push    114h
                0x68, 0x0B, 0x02, 0x00, 0x00,   // push    20Bh
                0x6A, 0x14                      // push    14h
                >(data); !s[0]) {
            logger.log_fail("Search ssl_read_internal");
            exit(1);
        } else {
            auto addr = (uintptr_t)(s[0] - data.data()) + base;
            if(!Hook(addr, &ssl_read_internal_hook, ssl_read_internal_org)) {
                logger.log_fail("Hook ssl_read_internal");
                exit(1);
            }
        }
        if (auto const s = Search< // 0x6CE5D0
                0xB8, 0x14, 0x00, 0x00, 0x00,   // mov     eax, 14h
                0xE8, Any, Any, Any, Any,       // call    j___alloca_probe
                0x56,                           // push    esi
                0x8B, 0x74, 0x24, 0x1C,         // mov     esi, [esp+18h+arg_0]
                0x83, 0x7E, 0x18, 0x00,         // cmp     dword ptr [esi+18h], 0
                0x75, 0x26,                     // jnz     $+5
                0x68, Any, Any, Any, Any,       // push    ????
                0x68, Any, Any, Any, Any,       // push    offset aSslSslLibC ; "ssl\\ssl_lib.c"
                0x68, 0x14, 0x01, 0x00, 0x00,   // push    114h
                0x68, 0x0C, 0x02, 0x00, 0x00,   // push    20Ch
                0x6A, 0x14                      // push    14h
                >(data); !s[0]) {
            logger.log_fail("Search ssl_write_internal");
            exit(1);
        } else {
            auto addr = (uintptr_t)(s[0] - data.data()) + base;
            if (!Hook(addr, &ssl_write_internal_hook, ssl_write_internal_org))  {
                logger.log_fail("Hook ssl_write_internal");
                exit(1);
            }
        }
        if (auto const s = Search< // 0x6CC910
                0x57,                           // push    edi
                0xE8, Any, Any, Any, Any,       // call    BIO_s_socket
                0x50,                           // push    eax
                0xE8, Any, Any, Any, Any,       // call    BIO_new
                0x8B, 0xF8,                     // mov     edi, eax
                0x83, 0xC4, 04,                 // add     esp, 4
                0x85, 0xFF,                     // test    edi, edi
                0x75, 0x1F,                     // jnz     short loc_10024694
                0x68, Any, Any, Any, Any,       // push    ???
                0x68, Any, Any, Any, Any,       // push    "ssl\\ssl_lib.c"
                0x6A, 0x07,                     // push    7
                0x68, 0xC0, 0x00, 0x00, 0x00,   // push    0C0h
                0x6A, 0x14                      // push    14h
                >(data); !s[0]) {
            logger.log_fail("Search SSL_set_fd");
            exit(1);
        } else {
            auto addr = (uintptr_t)(s[0] - data.data()) + base;
            if (!Hook(addr, &SSL_set_fd_hook, SSL_set_fd_org))  {
                logger.log_fail("Hook SSL_set_fd");
                exit(1);
            }
        }
        MH_ApplyQueued();
    }
};
#else
#endif

static Init init = {};
