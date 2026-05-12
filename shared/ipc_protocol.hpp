#pragma once

/*
 *  -> shared/ipc_protocol.hpp
 *  shared memory layout: "Local\memtrace_<pid>"
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace ipc {

    static constexpr std::uint32_t kMagic = 0x4D544943u;
    static constexpr std::uint32_t kVersion = 1u;
    static constexpr std::uint32_t kRingCapacity = 16384u;   /* power of two */
    static constexpr std::uint32_t kRingMask = kRingCapacity - 1u;
    static constexpr std::uint32_t kMaxStackFrames = 8u;

    static_assert((kRingCapacity& kRingMask) == 0,
        "kRingCapacity must be a power of two");

    enum class EventType : std::uint8_t {
        Invalid = 0,
        Alloc = 1,
        Free = 2,
        Realloc = 3,
    };

#pragma pack(push, 8)
    struct AllocEvent {
        std::uint64_t ptr;
        std::uint64_t old_ptr;
        std::uint64_t size;
        std::uint64_t timestamp_qpc;
        std::uint32_t thread_id;
        EventType     type;
        std::uint8_t  stack_depth;
        std::uint8_t  _pad[2];
        std::uint64_t stack[kMaxStackFrames];

        volatile std::uint64_t seq;
    };
#pragma pack(pop)

#pragma pack(push, 8)
    struct SharedHeader {
        /* identity */
        std::uint32_t magic;
        std::uint32_t version;
        std::uint32_t target_pid;
        std::uint32_t _pad0;

        /* handshake */ 
        volatile LONG payload_ready;
        volatile LONG host_attached;
        volatile LONG request_unload;
        std::uint32_t _pad1;

        alignas(64) volatile std::uint64_t reserve_pos;
        alignas(64) volatile std::uint64_t write_pos;
        alignas(64) volatile std::uint64_t read_pos;
        alignas(64) volatile std::uint64_t total_alloc_count;
        volatile std::uint64_t total_free_count;
        volatile std::uint64_t total_alloc_bytes;
        volatile std::uint64_t live_alloc_bytes;
        volatile std::uint64_t peak_alloc_bytes;
        volatile std::uint64_t dropped_events;
    };
#pragma pack(pop)

    static constexpr std::size_t kSharedMemSize =
        sizeof(SharedHeader) + kRingCapacity * sizeof(AllocEvent);


    /* name helpers */

    namespace detail {
        inline void u32_to_str(char* out, int& len, std::uint32_t v) noexcept {
            if (v == 0) { out[len++] = '0'; return; }
            char tmp[12]; int n = 0;
            while (v) { tmp[n++] = static_cast<char>('0' + v % 10); v /= 10; }
            for (int i = n - 1; i >= 0; --i) out[len++] = tmp[i];
        }
    }

    inline void make_shm_name(char* buf, std::size_t cap, std::uint32_t pid) noexcept {
        const char* pfx = "Local\\memtrace_";
        int i = 0;
        while (*pfx && static_cast<std::size_t>(i) + 1 < cap) buf[i++] = *pfx++;
        detail::u32_to_str(buf, i, pid);
        buf[i] = '\0';
    }

    inline void make_ready_event_name(char* buf, std::size_t cap, std::uint32_t pid) noexcept {
        const char* pfx = "Local\\memtrace_ready_";
        int i = 0;
        while (*pfx && static_cast<std::size_t>(i) + 1 < cap) buf[i++] = *pfx++;
        detail::u32_to_str(buf, i, pid);
        buf[i] = '\0';
    }

}