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

#ifndef WIN32
static_assert(sizeof(void*) == 8, "Compile in 64bit mode only!");
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
static_assert(sizeof(void*) == 4, "Compile in 32bit mode");
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
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
        send({"end", 0, time(), 0, 0 }, nullptr);
    }

    void log_fail(char const* desc) noexcept {
        send({"fail", 0, time(), 0, (uint32_t)strlen(desc) }, desc);
        file.flush();
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
            send({"fd_peer", (uintptr_t)s, t, (uint32_t)fd, 0}, nullptr);
        } else {
            send({"fd_peer", (uintptr_t)s, t, (uint32_t)fd, (uint32_t)addrlen}, &addr);
        }
        memset(&addr, 0, sizeof(addr));
        addrlen = sizeof(addr);
        if (getsockname(fd, &addr.addr, &addrlen) != 0) {
            send({"fd_sock", (uintptr_t)s, t, (uint32_t)fd, 0}, nullptr);
        } else {
            send({"fd_sock", (uintptr_t)s, t, (uint32_t)fd, (uint32_t)addrlen}, &addr);
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

#define assert(what) do { if (!(what)) { logger.log_fail(#what); exit(1); } } while(false)

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

#ifndef WIN32
template<typename T>
static bool hook_fn(char const* name, T* hook, T*& org) noexcept {
    void* trgt = nullptr;
    if (MH_CreateHookApiEx(nullptr, name, (void*)hook, (void**)&org, &trgt) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(trgt) != MH_OK) {
        return false;
    }
    return true;
}

struct Init {
    Init() {
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
        assert(hook_fn("ssl_read_internal", &ssl_read_internal_hook, ssl_read_internal_org));
        assert(hook_fn("ssl_write_internal", &ssl_write_internal_hook, ssl_write_internal_org));
        assert(hook_fn("SSL_set_fd", &SSL_set_fd_hook, SSL_set_fd_org));
        assert(MH_ApplyQueued() == MH_OK);
    }
};
static Init init = {};
#else
inline constexpr uint16_t Any = 0x0100u;
inline constexpr uint16_t Cap = 0x0200u;
template <uint16_t... ops>
inline auto Search(std::vector<uint8_t> const& data) noexcept {
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
    } (data.data(), data.size());
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

    void apply(uintptr_t base) const noexcept {
        assert(valid());
        assert(MH_Initialize() == MH_OK);
        assert(hook_fn(base + read, &ssl_read_internal_hook, ssl_read_internal_org));
        assert(hook_fn(base + write, &ssl_write_internal_hook, ssl_write_internal_org));
        assert(hook_fn(base + set_fd, &SSL_set_fd_hook, SSL_set_fd_org));
        assert(MH_ApplyQueued() == MH_OK);
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
    logger.log_start();
    auto base = (uintptr_t)GetModuleHandleA(nullptr);
    auto handle = GetCurrentProcess();
    auto checksum = uintptr_t{0};
    auto size = size_t{0};
    {
        char raw[1024] = {};
        assert(ReadProcessMemory(handle, (void const *)base, raw, sizeof(raw), nullptr));
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
        for (size_t i = 0; i < (size + 0x1000); i += 0x1000) {
            ReadProcessMemory(handle, (void const*)(base + i), data.data() + i, 0x1000, nullptr);
        }
        auto search_ssl_read = Search< //
                               0xB8, 0x14, 0x00, 0x00, 0x00,   // mov   eax, 14h
                               0xE8, Any, Any, Any, Any,       // call  j___alloca_probe
                               0x56,                           // push  esi
                               0x8B, 0x74, 0x24, 0x1C,         // mov   esi, [esp+18h+arg_0]
                               0x83, 0x7E, 0x18, 0x00,         // cmp   dword ptr [esi+18h], 0
                               0x75, 0x26,                     // jnz   $+5
                               0x68, Any, Any, Any, Any,       // push  ????
                               0x68, Any, Any, Any, Any,       // push  "ssl\\ssl_lib.c"
                               0x68, 0x14, 0x01, 0x00, 0x00,   // push  114h
                               0x68, 0x0B, 0x02, 0x00, 0x00,   // push  20Bh
                               0x6A, 0x14                      // push  14h
                               >(data);
        assert(search_ssl_read[0]);
        config.read = (uintptr_t)(search_ssl_read[0] - data.data());
        auto search_ssl_write = Search< //
                                0xB8, 0x14, 0x00, 0x00, 0x00,   // mov  eax, 14h
                                0xE8, Any, Any, Any, Any,       // call j___alloca_probe
                                0x56,                           // push esi
                                0x8B, 0x74, 0x24, 0x1C,         // mov  esi, [esp+18h+arg_0]
                                0x83, 0x7E, 0x18, 0x00,         // cmp  dword ptr [esi+18h], 0
                                0x75, 0x26,                     // jnz  $+5
                                0x68, Any, Any, Any, Any,       // push ????
                                0x68, Any, Any, Any, Any,       // push "ssl\\ssl_lib.c"
                                0x68, 0x14, 0x01, 0x00, 0x00,   // push 114h
                                0x68, 0x0C, 0x02, 0x00, 0x00,   // push 20Ch
                                0x6A, 0x14                      // push 14h
                                >(data);
        assert(search_ssl_write[0]);
        config.write = (uintptr_t)(search_ssl_write[0] - data.data());
        auto search_fd_set = Search< //
                             0x57,                           // push edi
                             0xE8, Any, Any, Any, Any,       // call BIO_s_socket
                             0x50,                           // push eax
                             0xE8, Any, Any, Any, Any,       // call BIO_new
                             0x8B, 0xF8,                     // mov  edi, eax
                             0x83, 0xC4, 04,                 // add  esp, 4
                             0x85, 0xFF,                     // test edi, edi
                             0x75, 0x1F,                     // jnz  short loc_10024694
                             0x68, Any, Any, Any, Any,       // push ???
                             0x68, Any, Any, Any, Any,       // push "ssl\\ssl_lib.c"
                             0x6A, 0x07,                     // push 7
                             0x68, 0xC0, 0x00, 0x00, 0x00,   // push 0C0h
                             0x6A, 0x14                      // push 14h
                             >(data);
        assert(search_fd_set[0]);
        config.set_fd = (uintptr_t)(search_fd_set[0] - data.data());
        config.checksum = checksum;
        config.save(folder);
    }
    config.apply(base);
    return TRUE;
}
#endif
