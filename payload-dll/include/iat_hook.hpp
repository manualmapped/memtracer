#pragma once

/*
 *  -> payload-dll/include/iat_hook.hpp
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace payload {

    /* data types */
    
    static constexpr int kMaxHooks = 64;

    struct Hook {
        void** iat_slot;
        void* original_fn;
        void* detour_fn;
        char    name[64];
        bool    installed;
    };
    inline bool install_iat_hook(HMODULE    module_base,
        const char* import_name,
        void* detour,
        void** out_original) noexcept
    {
        if (!module_base || !import_name || !detour || !out_original) return false;

        auto base = reinterpret_cast<std::uint8_t*>(module_base);

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const DWORD imp_rva = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress;
        if (imp_rva == 0) return false;

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + imp_rva);

        for (; desc->Name; ++desc) {
            auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->FirstThunk);
            auto* ofts = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + desc->OriginalFirstThunk);

            for (; iat->u1.Function; ++iat, ++ofts) {
                if (IMAGE_SNAP_BY_ORDINAL64(ofts->u1.Ordinal)) continue;

                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    base + ofts->u1.AddressOfData);

                if (std::strcmp(reinterpret_cast<const char*>(ibn->Name), import_name) != 0)
                    continue;

                void** slot = reinterpret_cast<void**>(&iat->u1.Function);
                *out_original = *slot;

                DWORD old_prot = 0;
                if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old_prot))
                    return false;

                *slot = detour;

                VirtualProtect(slot, sizeof(void*), old_prot, &old_prot);
                return true;
            }
        }
        return false;
    }

    inline void uninstall_iat_hook(Hook& h) noexcept {
        if (!h.installed || !h.iat_slot) return;
        DWORD old_prot = 0;
        VirtualProtect(h.iat_slot, sizeof(void*), PAGE_READWRITE, &old_prot);
        *h.iat_slot = h.original_fn;
        VirtualProtect(h.iat_slot, sizeof(void*), old_prot, &old_prot);
        h.installed = false;
    }

} 