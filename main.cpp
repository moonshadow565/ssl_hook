#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <fstream>
#include <chrono>
#include <string>
#include <cstring>
#include <ctime>
#include <filesystem>
#ifndef NDEBUG
#error "Compile in release mode only"
#endif
#ifdef WIN32
static_assert(sizeof(void*) == 4, "Compile in 32bit mode only!");
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#define ssl_read_internal_addr 0x2CDD50
#define ssl_write_internal_addr 0x2CE5D0
#define SSL_set_fd_addr 0x2CC910
#include <Windows.h>
#include <WinSock2.h>
static uintptr_t GetBaseAddress() {
    return (uintptr_t)GetModuleHandleA(nullptr);
}
#else
#error "implement GetBaseAddress for not WIN32"
static_assert(sizeof(void*) == 8, "Compile in 64bit mode only!");
#endif
#include "MinHook.h"

struct Logger {
    std::chrono::steady_clock clock = {};
    std::ofstream file = {};
    std::mutex lock = {};

    int64_t time() const noexcept {
        auto epoch = clock.now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
    }

    void open(std::filesystem::path folder) {
        std::filesystem::create_directories(folder);
        auto timestamp = std::chrono::seconds(std::time(nullptr)).count();
        file.open(folder / ("log_" + std::to_string(timestamp) + ".bin"), std::ios::binary);
    }

    void log(char const* type, void const* s, void const* data, size_t size) {
        struct Header {
            char type[8] = {};
            int64_t time = {};
            uint64_t ssl = {};
            uint64_t size = {};
        };
        static_assert (sizeof(Header) == 32);
        char pad[16] = {};
        Header header = {};
        strcpy(header.type, type);
        header.time = time();
        header.ssl = (uintptr_t)s;
        header.size = (size_t)size;
        file.write((char const*)&header, sizeof(Header));
        file.write((char const*)data, (std::streamsize)size);
        auto remain = size % sizeof(pad);
        if (remain) {
            file.write(pad, (std::streamsize)(sizeof(pad) - remain));
        }
    }

    void log_msg(char const* type, void const* s, void const* data, size_t size) {
        std::lock_guard<std::mutex> guard{lock};
        log(type, s, data, size);
    }

    void log_fd(char const* type, void const* s, int fd) {
        std::lock_guard<std::mutex> guard{lock};
        union {
            sockaddr addr;
            sockaddr_in addr4;
        } peer;
        memset(&peer, 0, sizeof(peer));
        int addrlen = sizeof(peer);
        if (getpeername(fd, &peer.addr, &addrlen) != 0) {
            return;
        }
        log(type, s, &peer, (size_t)addrlen);
    }
};

static Logger logger = {};
extern "C" {
static int (*ssl_read_internal_org)(void* s, void* buf, size_t num, size_t *readbytes);
static int ssl_read_internal_hook(void* s, void* buf, size_t num, size_t *readbytes) {
    int result = ssl_read_internal_org(s, buf, num, readbytes);
    if (result > 0 && *readbytes) {
        logger.log_msg("read", s, buf, *readbytes);
    }
    return result;
}
static int (*ssl_write_internal_org)(void* s, void const* buf, size_t num, size_t *written);
static int ssl_write_internal_hook(void* s, void const* buf, size_t num, size_t *written) {
    int result = ssl_write_internal_org(s, buf, num, written);
    if (result > 0 && *written) {
        logger.log_msg("write", s, buf, *written);
    }
    return result;
}
static int (*SSL_set_fd_org)(void *s, int fd);
static int SSL_set_fd_hook(void *s, int fd) {
    int result = SSL_set_fd_org(s, fd);
    if (result == 1) {
        logger.log_fd("set_fd", s, fd);
    }
    return result;
}
}

/*
.rdata:10067EF0 00 B0 20 14                         dd 1420B000h
.rdata:10067EF4 E0 A6 06 10                         dd offset aSslReadInterna ; "ssl_read_internal"
68 0B 02 00 00 6A 14

.rdata:10068058 00 C0 20 14                         dd 1420C000h
.rdata:1006805C 24 AB 06 10                         dd offset aSslWriteIntern ; "ssl_write_internal"
68 0C 02 00 00 6A 14

.rdata:10067F68 00 00 0C 14                         dd 140C0000h
.rdata:10067F6C 34 A8 06 10                         dd offset aSslSetFd_0   ; "SSL_set_fd"
.text:10024688 E8 75 66 03 00                       call    ERR_put_error
68 C0 00 00 00 6A 14
*/

struct Init {
    Init() {
        logger.open("./ssl_logs");
        auto base = GetBaseAddress();
        MH_Initialize();
        MH_CreateHook((void*)(base + ssl_read_internal_addr),
                      (void*)&ssl_read_internal_hook,
                      (void**)&ssl_read_internal_org);
        MH_EnableHook((void*)(base + ssl_read_internal_addr));
        MH_CreateHook((void*)(base + ssl_write_internal_addr),
                      (void*)&ssl_write_internal_hook,
                      (void**)&ssl_write_internal_org);
        MH_EnableHook((void*)(base + ssl_write_internal_addr));
        MH_CreateHook((void*)(base + SSL_set_fd_addr),
                      (void*)&SSL_set_fd_hook,
                      (void**)&SSL_set_fd_org);
        MH_EnableHook((void*)(base + SSL_set_fd_addr));
    }
};
static Init init = {};


