/*
 *  -> payload-dll/src/dllmain.cpp
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <psapi.h>
#include <intrin.h>

#include "../../shared/ipc_protocol.hpp"
#include "../include/iat_hook.hpp"

#pragma comment(lib, "psapi.lib")

/* globals */

static HANDLE              g_shm_handle = nullptr;
static ipc::SharedHeader* g_hdr = nullptr;
static ipc::AllocEvent* g_ring = nullptr;

static DWORD g_tls_idx = TLS_OUT_OF_INDEXES;

static volatile LONG64 g_reserve_pos = 0;

/* func pointers (original) */

using PFN_HeapAlloc = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);
using PFN_HeapFree = BOOL(WINAPI*)(HANDLE, DWORD, LPVOID);
using PFN_HeapReAlloc = LPVOID(WINAPI*)(HANDLE, DWORD, LPVOID, SIZE_T);
using PFN_VirtualAlloc = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using PFN_VirtualFree = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);

using PFN_malloc = void* (*)(size_t);
using PFN_free = void   (*)(void*);
using PFN_realloc = void* (*)(void*, size_t);
using PFN_calloc = void* (*)(size_t, size_t);

static PFN_HeapAlloc   orig_HeapAlloc = nullptr;
static PFN_HeapFree    orig_HeapFree = nullptr;
static PFN_HeapReAlloc orig_HeapReAlloc = nullptr;
static PFN_VirtualAlloc orig_VirtualAlloc = nullptr;
static PFN_VirtualFree orig_VirtualFree = nullptr;

static PFN_malloc  orig_malloc = nullptr;
static PFN_free    orig_free = nullptr;
static PFN_realloc orig_realloc = nullptr;
static PFN_calloc  orig_calloc = nullptr;

/* guard */

static __forceinline bool hook_try_enter() noexcept
{
    if (g_tls_idx == TLS_OUT_OF_INDEXES)
        return false;

    if (TlsGetValue(g_tls_idx))
        return false;

    TlsSetValue(g_tls_idx, reinterpret_cast<void*>(1));
    return true;
}

static __forceinline void hook_leave() noexcept
{
    if (g_tls_idx != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_idx, nullptr);
}

/* qpc helper */

static __forceinline UINT64 qpc() noexcept
{
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return static_cast<UINT64>(li.QuadPart);
}

/* ring push */

static __forceinline void push_event(
    ipc::EventType type,
    UINT64 ptr,
    UINT64 old_ptr,
    UINT64 size) noexcept
{
    if (!g_hdr || !g_ring)
        return;

    /* reserve */
    const UINT64 pos =
        static_cast<UINT64>(
            InterlockedIncrement64(&g_reserve_pos)) - 1ULL;

    const UINT64 rpos = g_hdr->read_pos;

    /* full ring */
    if ((pos - rpos) >= ipc::kRingCapacity) {
        InterlockedIncrement64(
            reinterpret_cast<volatile LONG64*>(
                &g_hdr->dropped_events));
        return;
    }

    ipc::AllocEvent& ev =
        g_ring[pos & ipc::kRingMask];

    ZeroMemory(&ev, sizeof(ev));

    /* payload fields */
    ev.ptr = ptr;
    ev.old_ptr = old_ptr;
    ev.size = size;
    ev.timestamp_qpc = qpc();
    ev.thread_id = GetCurrentThreadId();
    ev.type = type;
   /*   capture stack | frame layout 
    *   0 = RtlCaptureStackBackTrace (internal)
    *   1 = push_event (this function)
    *   2 = detour_xxx (malloc/calloc/HeapAlloc hook)
    *   3 = CRT wrapper (_malloc_dbg)
    *   4 = application allocation wrapper (if any)
    *   5 = actual application caller
    */
    void* frames[ipc::kMaxStackFrames] = {};

    USHORT captured =
        RtlCaptureStackBackTrace(
            5,
            ipc::kMaxStackFrames,
            frames,
            nullptr);

    if (captured > ipc::kMaxStackFrames)
        captured = ipc::kMaxStackFrames;

    ev.stack_depth = static_cast<std::uint8_t>(captured);

    for (USHORT i = 0; i < captured; ++i)
    {
        ev.stack[i] =
            reinterpret_cast<std::uint64_t>(frames[i]);
    }

    InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&ev.seq),
        static_cast<LONG64>(pos));

    while (g_hdr->write_pos != pos)
        YieldProcessor();

    InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&g_hdr->write_pos),
        static_cast<LONG64>(pos + 1ULL));

    if (type == ipc::EventType::Alloc ||
        type == ipc::EventType::Realloc)
    {
        InterlockedIncrement64(
            reinterpret_cast<volatile LONG64*>(
                &g_hdr->total_alloc_count));

        InterlockedExchangeAdd64(
            reinterpret_cast<volatile LONG64*>(
                &g_hdr->total_alloc_bytes),
            static_cast<LONG64>(size));

        LONG64 live =
            InterlockedExchangeAdd64(
                reinterpret_cast<volatile LONG64*>(
                    &g_hdr->live_alloc_bytes),
                static_cast<LONG64>(size))
            + static_cast<LONG64>(size);

        LONG64 peak =
            static_cast<LONG64>(g_hdr->peak_alloc_bytes);

        while (live > peak)
        {
            LONG64 old =
                InterlockedCompareExchange64(
                    reinterpret_cast<volatile LONG64*>(
                        &g_hdr->peak_alloc_bytes),
                    live,
                    peak);

            if (old == peak)
                break;

            peak = old;
        }
    }
    else if (type == ipc::EventType::Free)
    {
        InterlockedIncrement64(
            reinterpret_cast<volatile LONG64*>(
                &g_hdr->total_free_count));

        InterlockedExchangeAdd64(
            reinterpret_cast<volatile LONG64*>(
                &g_hdr->live_alloc_bytes),
            -static_cast<LONG64>(size));
    }
}

/* hooks */

static LPVOID WINAPI detour_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect)
{
    LPVOID p = orig_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    if (p && hook_try_enter()) {
        push_event(
            ipc::EventType::Alloc,
            reinterpret_cast<UINT64>(p),
            0,
            static_cast<UINT64>(dwSize));
        hook_leave();
    }

    return p;
}

static BOOL WINAPI detour_VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType)
{
    if (lpAddress && hook_try_enter()) {
        push_event(
            ipc::EventType::Free,
            reinterpret_cast<UINT64>(lpAddress),
            0,
            static_cast<UINT64>(dwSize));
        hook_leave();
    }

    return orig_VirtualFree(lpAddress, dwSize, dwFreeType);
}

static LPVOID WINAPI detour_HeapAlloc(
    HANDLE h,
    DWORD f,
    SIZE_T n)
{
    LPVOID p = orig_HeapAlloc(h, f, n);

    if (p && hook_try_enter()) {
        push_event(
            ipc::EventType::Alloc,
            reinterpret_cast<UINT64>(p),
            0,
            static_cast<UINT64>(n));
        hook_leave();
    }

    return p;
}

static BOOL WINAPI detour_HeapFree(
    HANDLE h,
    DWORD f,
    LPVOID p)
{
    if (p && hook_try_enter()) {
        push_event(
            ipc::EventType::Free,
            reinterpret_cast<UINT64>(p),
            0,
            0);
        hook_leave();
    }

    return orig_HeapFree(h, f, p);
}

static LPVOID WINAPI detour_HeapReAlloc(
    HANDLE h,
    DWORD f,
    LPVOID p,
    SIZE_T n)
{
    LPVOID q = orig_HeapReAlloc(h, f, p, n);

    if (q && hook_try_enter()) {
        push_event(
            ipc::EventType::Realloc,
            reinterpret_cast<UINT64>(q),
            reinterpret_cast<UINT64>(p),
            static_cast<UINT64>(n));
        hook_leave();
    }

    return q;
}

static void* detour_malloc(size_t n)
{
    void* p = orig_malloc(n);

    if (p && hook_try_enter()) {
        push_event(
            ipc::EventType::Alloc,
            reinterpret_cast<UINT64>(p),
            0,
            static_cast<UINT64>(n));
        hook_leave();
    }

    return p;
}

static void detour_free(void* p)
{
    if (p && hook_try_enter()) {
        push_event(
            ipc::EventType::Free,
            reinterpret_cast<UINT64>(p),
            0,
            0);
        hook_leave();
    }

    orig_free(p);
}

static void* detour_realloc(void* p, size_t n)
{
    void* q = orig_realloc(p, n);

    if (q && hook_try_enter()) {
        push_event(
            ipc::EventType::Realloc,
            reinterpret_cast<UINT64>(q),
            reinterpret_cast<UINT64>(p),
            static_cast<UINT64>(n));
        hook_leave();
    }

    return q;
}

static void* detour_calloc(size_t c, size_t n)
{
    void* p = orig_calloc(c, n);

    if (p && hook_try_enter()) {
        push_event(
            ipc::EventType::Alloc,
            reinterpret_cast<UINT64>(p),
            0,
            static_cast<UINT64>(c * n));
        hook_leave();
    }

    return p;
}

/* hook table */

struct HookSpec {
    const char* name;
    void* detour;
    void** orig;
};

static HookSpec kSpecs[] = {
    { "HeapAlloc",   (void*)detour_HeapAlloc,   (void**)&orig_HeapAlloc   },
    { "HeapFree",    (void*)detour_HeapFree,    (void**)&orig_HeapFree    },
    { "HeapReAlloc", (void*)detour_HeapReAlloc, (void**)&orig_HeapReAlloc },
    { "VirtualAlloc", (void*)detour_VirtualAlloc, (void**)&orig_VirtualAlloc },
    { "VirtualFree",  (void*)detour_VirtualFree,  (void**)&orig_VirtualFree },
    { "malloc",      (void*)detour_malloc,      (void**)&orig_malloc      },
    { "free",        (void*)detour_free,        (void**)&orig_free        },
    { "realloc",     (void*)detour_realloc,     (void**)&orig_realloc     },
    { "calloc",      (void*)detour_calloc,      (void**)&orig_calloc      },
};

/* hook install */

static void seed_originals() noexcept
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");

    HMODULE crt = GetModuleHandleA("ucrtbase.dll");
    if (!crt)
        crt = GetModuleHandleA("msvcrt.dll");

    if (k32)
    {
        orig_HeapAlloc =
            (PFN_HeapAlloc)GetProcAddress(k32, "HeapAlloc");

        orig_HeapFree =
            (PFN_HeapFree)GetProcAddress(k32, "HeapFree");

        orig_HeapReAlloc =
            (PFN_HeapReAlloc)GetProcAddress(k32, "HeapReAlloc");

        orig_VirtualAlloc = 
            (PFN_VirtualAlloc)GetProcAddress(k32, "VirtualAlloc");

        orig_VirtualFree = 
            (PFN_VirtualFree)GetProcAddress(k32, "VirtualFree");
    }

    if (crt)
    {
        orig_malloc =
            (PFN_malloc)GetProcAddress(crt, "malloc");

        orig_free =
            (PFN_free)GetProcAddress(crt, "free");

        orig_realloc =
            (PFN_realloc)GetProcAddress(crt, "realloc");

        orig_calloc =
            (PFN_calloc)GetProcAddress(crt, "calloc");
    }
}

static void install_hooks() noexcept
{
    seed_originals();

    HMODULE exe = GetModuleHandleA(nullptr);

    for (size_t i = 0; i < (sizeof(kSpecs) / sizeof(kSpecs[0])); ++i)
    {
        void* orig = nullptr;

        if (payload::install_iat_hook(
            exe,
            kSpecs[i].name,
            kSpecs[i].detour,
            &orig))
        {
            if (orig && !*kSpecs[i].orig)
                *kSpecs[i].orig = orig;
        }
    }
}

/* shared memory */

static bool shm_create(DWORD pid) noexcept
{
    char name[128] = {};
    ipc::make_shm_name(name, sizeof(name), pid);

    const DWORD sz =
        static_cast<DWORD>(ipc::kSharedMemSize);

    g_shm_handle =
        CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            nullptr,
            PAGE_READWRITE,
            0,
            sz,
            name);

    if (!g_shm_handle)
        return false;

    void* view =
        MapViewOfFile(
            g_shm_handle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            0);

    if (!view)
    {
        CloseHandle(g_shm_handle);
        g_shm_handle = nullptr;
        return false;
    }

    g_hdr =
        reinterpret_cast<ipc::SharedHeader*>(view);

    g_ring =
        reinterpret_cast<ipc::AllocEvent*>(
            reinterpret_cast<BYTE*>(view)
            + sizeof(ipc::SharedHeader));

    ZeroMemory(view, ipc::kSharedMemSize);

    g_hdr->magic = ipc::kMagic;
    g_hdr->version = ipc::kVersion;
    g_hdr->target_pid = pid;

    for (UINT32 i = 0; i < ipc::kRingCapacity; ++i)
        g_ring[i].seq = UINT64_MAX;

    return true;
}

static void shm_destroy() noexcept
{
    if (g_hdr) {
        UnmapViewOfFile(g_hdr);
        g_hdr = nullptr;
        g_ring = nullptr;
    }

    if (g_shm_handle) {
        CloseHandle(g_shm_handle);
        g_shm_handle = nullptr;
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD reason,
    LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hinstDLL);

        g_tls_idx = TlsAlloc();

        if (g_tls_idx == TLS_OUT_OF_INDEXES)
            return FALSE;

        const DWORD pid = GetCurrentProcessId();

        if (!shm_create(pid))
        {
            TlsFree(g_tls_idx);
            g_tls_idx = TLS_OUT_OF_INDEXES;
            return FALSE;
        }

        install_hooks();

        InterlockedExchange(
            &g_hdr->payload_ready,
            1);

        char ev_name[128] = {};

        ipc::make_ready_event_name(
            ev_name,
            sizeof(ev_name),
            pid);

        HANDLE ev =
            OpenEventA(
                EVENT_MODIFY_STATE,
                FALSE,
                ev_name);

        if (ev) {
            SetEvent(ev);
            CloseHandle(ev);
        }

        break;
    }

    case DLL_PROCESS_DETACH:
    {
        shm_destroy();

        if (g_tls_idx != TLS_OUT_OF_INDEXES)
        {
            TlsFree(g_tls_idx);
            g_tls_idx = TLS_OUT_OF_INDEXES;
        }

        break;
    }
    }

    return TRUE;
}