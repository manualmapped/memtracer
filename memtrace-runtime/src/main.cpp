/*
 *  -> memtrace-runtime/src/main.cpp
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>

#include "../../shared/ipc_protocol.hpp"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

#ifdef _MSC_VER
#  pragma warning(disable: 4100)  /* unreferenced formal parameter */
#  pragma warning(disable: 4201)  /* nameless struct/union */
#  pragma warning(disable: 4996)  /* 'sprintf': deprecated */
#  pragma warning(disable: 26451) /* /arithmetic overflow (intentional byte maths) */
#endif

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

/* configuration */
struct Config {
    DWORD        pid = 0;
    std::string  launch_exe;
    std::string  launch_args;
    DWORD        report_interval_ms = 1000;
    int          top_allocs = 10;
    std::string  output_file;
    bool         show_stack = false;
    bool         dump_all_stacks = false;
    std::size_t  threshold_bytes = 0;
    int          duration_s = 0;
    bool         no_color = false;
    bool         quiet = false;
    std::string  dll_path; /* auto detected (dll and memtrace needs to be in the same folder) */
};

/* live allocation tracking */

struct AllocSite {
    std::uint64_t total_bytes = 0;
    std::uint64_t count = 0;
    std::uint64_t stack[ipc::kMaxStackFrames] = {};
    std::uint8_t  stack_depth = 0;
    std::uint64_t last_sample_bytes = 0;
    std::chrono::steady_clock::time_point last_sample_time;
};

struct SiteSnapshot {
    std::uint64_t total_bytes = 0;
    std::chrono::steady_clock::time_point timestamp;
};

struct LiveState {
    std::mutex                                   mtx;
    std::unordered_map<std::uint64_t, std::uint64_t> live; /* ptr->size* */
    std::unordered_map<std::uint64_t, AllocSite> sites;    /* stack_key -> site */
    std::unordered_map<std::uint64_t, std::vector<SiteSnapshot>> site_history; /* growth tracking */
    std::uint64_t total_alloc_count = 0;
    std::uint64_t total_free_count = 0;
    std::uint64_t total_alloc_bytes = 0;
    std::uint64_t dropped_events = 0;
    std::uint64_t peak_bytes = 0;
    std::uint64_t current_bytes = 0;

    std::chrono::steady_clock::time_point last_growth_check;
    int growth_check_counter = 0;
};

static LiveState g_state;

/* ansi colors */
namespace col {
    static bool enabled = true;
    static const char* reset = "\033[0m";
    static const char* bold = "\033[1m";
    static const char* red = "\033[31m";
    static const char* yellow = "\033[33m";
    static const char* green = "\033[32m";
    static const char* cyan = "\033[36m";
    static const char* magenta = "\033[35m";
    static const char* dim = "\033[2m";
    inline const char* r() { return enabled ? reset : ""; }
    inline const char* b() { return enabled ? bold : ""; }
    inline const char* rd() { return enabled ? red : ""; }
    inline const char* yw() { return enabled ? yellow : ""; }
    inline const char* gn() { return enabled ? green : ""; }
    inline const char* cy() { return enabled ? cyan : ""; }
    inline const char* mg() { return enabled ? magenta : ""; }
    inline const char* dm() { return enabled ? dim : ""; }
}

/* helpers */

static std::string human_bytes(std::uint64_t n) {
    char buf[64];
    if (n >= 1024ULL * 1024 * 1024) std::snprintf(buf, sizeof(buf), "%.2f GiB", n / (1024.0 * 1024 * 1024));
    else if (n >= 1024ULL * 1024)        std::snprintf(buf, sizeof(buf), "%.2f MiB", n / (1024.0 * 1024));
    else if (n >= 1024ULL)               std::snprintf(buf, sizeof(buf), "%.2f KiB", n / 1024.0);
    else                                 std::snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)n);
    return buf;
}

static std::string resolve_symbol(HANDLE proc, std::uint64_t addr) {
    if (addr == 0) return "<null>";

    static std::unordered_map<std::uint64_t, std::string> symbol_cache;
    static std::mutex cache_mutex;

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = symbol_cache.find(addr);
        if (it != symbol_cache.end()) {
            return it->second;
        }
    }

    char buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * 2] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFO*>(buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    std::string result;

    if (SymFromAddr(proc, addr, &displacement, sym)) {
        IMAGEHLP_MODULE64 module = {};
        module.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

        char demangled[1024] = { 0 };
        const char* func_name = sym->Name;

        if (UnDecorateSymbolName(sym->Name, demangled, sizeof(demangled),
            UNDNAME_COMPLETE | UNDNAME_NO_ACCESS_SPECIFIERS | UNDNAME_NO_THROW_SIGNATURES)) {
            func_name = demangled;
        }

        if (SymGetModuleInfo64(proc, sym->ModBase, &module)) {
            const char* mod_name = module.ModuleName;
            const char* last_slash = strrchr(module.ImageName, '\\');
            if (!last_slash) last_slash = strrchr(module.ImageName, '/');
            if (last_slash) mod_name = last_slash + 1;

            char formatted[512];
            if (displacement > 0) {
                std::snprintf(formatted, sizeof(formatted), "%s!%s+0x%llx",
                    mod_name, func_name, (unsigned long long)displacement);
            }
            else {
                std::snprintf(formatted, sizeof(formatted), "%s!%s", mod_name, func_name);
            }
            result = formatted;
        }
        else {
            char formatted[256];
            if (displacement > 0) {
                std::snprintf(formatted, sizeof(formatted), "%s+0x%llx", func_name, (unsigned long long)displacement);
            }
            else {
                std::snprintf(formatted, sizeof(formatted), "%s", func_name);
            }
            result = formatted;
        }
    }
    else {
        char hex[32];
        std::snprintf(hex, sizeof(hex), "0x%016llx", (unsigned long long)addr);
        result = hex;
    }

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        symbol_cache[addr] = result;
    }

    return result;
}

static void print_stack_trace(HANDLE proc, const AllocSite& site, int max_frames = 5) {
    int printed = 0;
    for (int i = 0; i < std::min<int>(site.stack_depth, max_frames + 3); ++i) {
        std::string sym = resolve_symbol(proc, site.stack[i]);

        if (sym.find("_malloc_dbg") != std::string::npos ||
            sym.find("_free_dbg") != std::string::npos ||
            sym.find("_crt_") != std::string::npos ||
            sym.find("operator new") != std::string::npos ||
            sym.find("operator delete") != std::string::npos ||
            sym.find("RtlCapture") != std::string::npos) {
            continue;
        }

        std::printf("    %s[%d] %s%s\n", col::dm(), printed, sym.c_str(), col::r());
        printed++;
        if (printed >= max_frames) break;
    }
}

static void clear_screen() {
    HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD  top = { 0, 0 };
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (GetConsoleScreenBufferInfo(con, &info)) {
        DWORD written;
        DWORD cells = info.dwSize.X * info.dwSize.Y;
        FillConsoleOutputCharacterA(con, ' ', cells, top, &written);
        FillConsoleOutputAttribute(con, info.wAttributes, cells, top, &written);
    }
    SetConsoleCursorPosition(con, top);
}

/* growth analysis */

enum class SiteGrowth { Stable, Suspect, Growing };

struct SiteAnalysis {
    SiteGrowth classification;
    double growth_rate_pct;
    std::uint64_t bytes_added;
    std::chrono::seconds time_span;
};

static SiteAnalysis analyze_site_growth(const AllocSite& site,
    const SiteSnapshot& old_snapshot,
    const SiteSnapshot& new_snapshot) {
    SiteAnalysis result;

    auto time_span = std::chrono::duration_cast<std::chrono::seconds>(
        new_snapshot.timestamp - old_snapshot.timestamp);
    result.time_span = time_span;

    if (old_snapshot.total_bytes == 0) {
        result.classification = SiteGrowth::Growing;
        result.growth_rate_pct = 100.0;
        result.bytes_added = site.total_bytes;
        return result;
    }

    if (site.total_bytes > old_snapshot.total_bytes) {
        result.bytes_added = site.total_bytes - old_snapshot.total_bytes;
        result.growth_rate_pct = (static_cast<double>(result.bytes_added) /
            static_cast<double>(old_snapshot.total_bytes)) * 100.0;

        if (result.growth_rate_pct > 10.0) {
            result.classification = SiteGrowth::Growing;
        }
        else if (result.growth_rate_pct > 0) {
            result.classification = SiteGrowth::Suspect;
        }
        else {
            result.classification = SiteGrowth::Stable;
        }
    }
    else {
        result.bytes_added = 0;
        result.growth_rate_pct = 0;
        result.classification = SiteGrowth::Stable;
    }

    return result;
}

static void process_event(const ipc::AllocEvent& ev, const Config& cfg) {
    std::lock_guard<std::mutex> lk(g_state.mtx);

    if (ev.type == ipc::EventType::Alloc) {
        if (ev.size < cfg.threshold_bytes) return;
        g_state.live[ev.ptr] = ev.size;
        g_state.total_alloc_count++;
        g_state.total_alloc_bytes += ev.size;
        g_state.current_bytes += ev.size;
        if (g_state.current_bytes > g_state.peak_bytes)
            g_state.peak_bytes = g_state.current_bytes;

        std::uint64_t key = 0;
        for (int i = 0; i < ev.stack_depth && i < ipc::kMaxStackFrames; ++i) {
            key ^= (ev.stack[i] << (i * 5));
            key ^= (ev.stack[i] >> (64 - i * 3));
            key *= 0x9e3779b97f4a7c15ULL; /* golden ratio constant (I cook that lil' shit up, Green Eggs and Ham - Yeat ) */
        }

        auto& site = g_state.sites[key];
        site.total_bytes += ev.size;
        site.count++;
        site.stack_depth = ev.stack_depth;
        for (int i = 0; i < ev.stack_depth; ++i) site.stack[i] = ev.stack[i];

    }
    else if (ev.type == ipc::EventType::Free) {
        auto it = g_state.live.find(ev.ptr);
        if (it != g_state.live.end()) {
            if (g_state.current_bytes >= it->second)
                g_state.current_bytes -= it->second;
            g_state.live.erase(it);
        }
        g_state.total_free_count++;

    }
    else if (ev.type == ipc::EventType::Realloc) {
        auto it = g_state.live.find(ev.old_ptr);
        if (it != g_state.live.end()) {
            if (g_state.current_bytes >= it->second)
                g_state.current_bytes -= it->second;
            g_state.live.erase(it);
        }
        g_state.live[ev.ptr] = ev.size;
        g_state.total_alloc_count++;
        g_state.total_alloc_bytes += ev.size;
        g_state.current_bytes += ev.size;
        if (g_state.current_bytes > g_state.peak_bytes)
            g_state.peak_bytes = g_state.current_bytes;
    }
}

/* dashboard */

static void print_dashboard(const Config& cfg,
    HANDLE target_proc,
    const ipc::SharedHeader* hdr,
    double elapsed_s)
{
    clear_screen();

    std::printf("%s%s memtrace-runtime %s| target PID %-6lu | elapsed %.1fs %s\n",
        col::b(), col::cy(),
        col::r(),
        (unsigned long)hdr->target_pid,
        elapsed_s,
        col::r());

    std::printf("%s%s\n", col::dm(),
        "================================================================================");
    std::printf("%s\n", col::r());

    /* summary */
    std::string current_heap_color = (g_state.current_bytes > 1024ULL * 1024 * 1024) ? col::rd() : col::gn();
    std::printf("  %slive allocations:%s  %-12llu   %scurrent heap:%s  %s%s%s\n",
        col::b(), col::r(), (unsigned long long)g_state.live.size(),
        col::b(), col::r(), current_heap_color, human_bytes(g_state.current_bytes).c_str(), col::r());

    std::printf("  %speak heap:%s         %-12s   %stotal allocs:%s  %llu\n",
        col::b(), col::r(), human_bytes(g_state.peak_bytes).c_str(),
        col::b(), col::r(), (unsigned long long)g_state.total_alloc_count);

    std::printf("  %stotal freed:%s       %-12llu   %sdropped events:%s %llu\n",
        col::b(), col::r(), (unsigned long long)g_state.total_free_count,
        col::b(), col::r(), (unsigned long long)hdr->dropped_events);

    std::printf("\n");

    std::printf("  %s%stop %d allocation sites by total bytes (growth since last sample):%s\n",
        col::b(), col::yw(), cfg.top_allocs, col::r());
    std::printf("  %s%-8s  %-12s  %-10s  %s%s\n", col::dm(),
        "count", "total", "growth", "call-site", col::r());
    std::printf("  %s%s%s\n", col::dm(),
        "--------  ------------  ----------  ------------------------------------------------", col::r());

    struct SiteEntry { std::uint64_t key; const AllocSite* site; };
    std::vector<SiteEntry> sorted;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        sorted.reserve(g_state.sites.size());
        for (const auto& [k, v] : g_state.sites) sorted.push_back({ k, &v });
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const SiteEntry& a, const SiteEntry& b) {
            return a.site->total_bytes > b.site->total_bytes;
        });

    auto now = std::chrono::steady_clock::now();

    static bool initial_snapshot_taken = false;
    static std::chrono::steady_clock::time_point last_snapshot_time;
    static std::unordered_map<std::uint64_t, SiteSnapshot> baseline_snapshots;

    if (!initial_snapshot_taken) {
        for (const auto& [key, site] : g_state.sites) {
            SiteSnapshot snap;
            snap.total_bytes = site.total_bytes;
            snap.timestamp = now;
            baseline_snapshots[key] = snap;
            g_state.site_history[key].clear();
            g_state.site_history[key].push_back(snap);
        }
        initial_snapshot_taken = true;
        last_snapshot_time = now;
    }

    bool should_analyze = false;
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_snapshot_time).count() >= 10) {
        for (const auto& [key, site] : g_state.sites) {
            SiteSnapshot new_snap;
            new_snap.total_bytes = site.total_bytes;
            new_snap.timestamp = now;

            if (g_state.site_history[key].size() >= 2) {
                g_state.site_history[key].erase(g_state.site_history[key].begin());
            }
            g_state.site_history[key].push_back(new_snap);
        }
        last_snapshot_time = now;
        should_analyze = true;
    }

    int shown = 0;
    for (const auto& e : sorted) {
        if (shown >= cfg.top_allocs) break;
        const auto* s = e.site;

        std::string growth_str = "stable";
        const char* growth_color = col::gn();

        auto baseline_it = baseline_snapshots.find(e.key);
        auto hist_it = g_state.site_history.find(e.key);

        if (baseline_it != baseline_snapshots.end() && hist_it != g_state.site_history.end() && !hist_it->second.empty()) {
            const auto& baseline = baseline_it->second;
            const auto& current = hist_it->second.back();

            if (current.total_bytes > baseline.total_bytes) {
                double growth_pct = ((current.total_bytes - baseline.total_bytes) * 100.0) / baseline.total_bytes;

                if (growth_pct > 10.0) {
                    growth_str = std::to_string(static_cast<int>(growth_pct)) + "% [UP]";
                    growth_color = col::rd();
                }
                else if (growth_pct > 0) {
                    growth_str = std::to_string(static_cast<int>(growth_pct)) + "% [!]";
                    growth_color = col::yw();
                }
                else {
                    growth_str = "stable";
                    growth_color = col::gn();
                }
            }
            else if (current.total_bytes == baseline.total_bytes) {
                growth_str = "stable";
                growth_color = col::gn();
            }
            else {
                growth_str = "shrinking";
                growth_color = col::cy();
            }
        }
        else if (baseline_it == baseline_snapshots.end()) {
            SiteSnapshot snap;
            snap.total_bytes = s->total_bytes;
            snap.timestamp = now;
            baseline_snapshots[e.key] = snap;
            if (hist_it != g_state.site_history.end() && !hist_it->second.empty()) {
                hist_it->second.push_back(snap);
            }
            else {
                g_state.site_history[e.key].push_back(snap);
            }
            growth_str = "new";
            growth_color = col::cy();
        }

        const char* color = (s->total_bytes > 100 * 1024 * 1024) ? col::rd()
            : (s->total_bytes > 10 * 1024 * 1024) ? col::yw()
            : col::r();

        std::printf("  %-8llu  %s%-12s%s  %s%-10s%s  ",
            (unsigned long long)s->count,
            color, human_bytes(s->total_bytes).c_str(), col::r(),
            growth_color, growth_str.c_str(), col::r());

        if (cfg.show_stack && s->stack_depth > 0) {
            int display_frame = 0;
            for (int i = 0; i < s->stack_depth; ++i) {
                if (i < s->stack_depth && s->stack[i] != 0) {
                    std::string sym = resolve_symbol(target_proc, s->stack[i]);
                    if (sym.find("malloc") == std::string::npos &&
                        sym.find("free") == std::string::npos &&
                        sym.find("operator new") == std::string::npos &&
                        sym.find("operator delete") == std::string::npos &&
                        sym.find("RtlCapture") == std::string::npos &&
                        sym.find("_Structured") == std::string::npos) {
                        display_frame = i;
                        break;
                    }
                }
            }

            if (display_frame < s->stack_depth && s->stack[display_frame] != 0) {
                std::string sym = resolve_symbol(target_proc, s->stack[display_frame]);
                if (sym.length() > 80) {
                    sym = sym.substr(0, 77) + "...";
                }
                std::printf("%s\n", sym.c_str());

                int printed = 0;
                for (int f = 0; f < std::min<int>(s->stack_depth, 10) && printed < 3; ++f) {
                    if (f == display_frame) continue;
                    if (s->stack[f] == 0) continue;

                    std::string fs = resolve_symbol(target_proc, s->stack[f]);
                    if (fs.find("malloc") != std::string::npos ||
                        fs.find("free") != std::string::npos ||
                        fs.find("operator new") != std::string::npos ||
                        fs.find("operator delete") != std::string::npos ||
                        fs.find("RtlCapture") != std::string::npos) {
                        continue;
                    }
                    if (fs.length() > 70) fs = fs.substr(0, 67) + "...";
                    std::printf("  %s          [%d] %s%s\n", col::dm(), f, fs.c_str(), col::r());
                    printed++;
                }
            }
            else {
                std::printf("0x%016llx\n", (unsigned long long)s->stack[0]);
            }
        }
        else if (s->stack_depth > 0 && s->stack[0] != 0) {
            std::printf("0x%016llx\n", (unsigned long long)s->stack[0]);
        }
        else {
            std::printf("<no stack>\n");
        }
        ++shown;
    }

    std::uint64_t live_bytes = 0, live_count = 0;
    int growing_sites = 0;
    std::uint64_t growing_bytes = 0;

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        live_count = g_state.live.size();
        live_bytes = g_state.current_bytes;

        for (const auto& [key, baseline] : baseline_snapshots) {
            auto site_it = g_state.sites.find(key);
            if (site_it != g_state.sites.end()) {
                const auto& site = site_it->second;
                if (site.total_bytes > baseline.total_bytes) {
                    uint64_t growth = site.total_bytes - baseline.total_bytes;
                    double growth_pct = (growth * 100.0) / baseline.total_bytes;
                    if (growth_pct > 10.0 && growth > 1024) { /* >10 % and >1KB */
                        growing_sites++;
                        growing_bytes += growth;
                    }
                }
            }
        }
    }

    std::printf("\n  %s%slive allocations -> %llu allocations, %s%s\n",
        col::b(), (live_count > 0 && growing_sites > 0) ? col::rd() : (live_count > 0 ? col::yw() : col::gn()),
        (unsigned long long)live_count,
        human_bytes(live_bytes).c_str(),
        col::r());

    if (growing_sites > 0) {
        std::printf("  %s[!] %d actively growing allocation site(s) (+%s) - possible memory leak%s\n",
            col::rd(), growing_sites, human_bytes(growing_bytes).c_str(), col::r());
    }
    else if (live_count > 0) {
        std::printf("  %s[i] live allocations stable (no growth detected). likely caches/pools%s\n",
            col::cy(), col::r());
    }

    auto analysis_age = std::chrono::duration_cast<std::chrono::seconds>(now - last_snapshot_time).count();
    if (analysis_age < 10) {
        std::printf("  %s[next analysis in %ld seconds]%s\n",
            col::dm(), 10 - analysis_age, col::r());
    }

    std::printf("\n  %s[press Ctrl+C to stop and print final report]%s\n",
        col::dm(), col::r());
    std::fflush(stdout);
}

static void write_json_report(const Config& cfg, const ipc::SharedHeader* hdr) {
    std::ofstream f(cfg.output_file);
    if (!f.is_open()) {
        std::fprintf(stderr, "[memtrace] WARNING: could not open output file: %s\n",
            cfg.output_file.c_str());
        return;
    }

    f << "{\n";
    f << "  \"target_pid\": " << hdr->target_pid << ",\n";
    f << "  \"summary\": {\n";
    f << "    \"total_alloc_count\": " << g_state.total_alloc_count << ",\n";
    f << "    \"total_free_count\":  " << g_state.total_free_count << ",\n";
    f << "    \"total_alloc_bytes\": " << g_state.total_alloc_bytes << ",\n";
    f << "    \"peak_bytes\":        " << g_state.peak_bytes << ",\n";
    f << "    \"live_alloc_count\":  " << g_state.live.size() << ",\n";
    f << "    \"live_alloc_bytes\":  " << g_state.current_bytes << ",\n";
    f << "    \"dropped_events\":    " << hdr->dropped_events << "\n";
    f << "  },\n";


    f << "  \"live_allocations\": [\n";
    bool first = true;
    for (const auto& [ptr, size] : g_state.live) {
        if (!first) f << ",\n";
        f << "    {\"ptr\": " << ptr << ", \"size\": " << size << "}";
        first = false;
    }
    f << "\n  ],\n";

    f << "  \"top_sites\": [\n";
    struct SiteEntry { std::uint64_t key; AllocSite site; };
    std::vector<SiteEntry> sorted;
    for (const auto& [k, v] : g_state.sites) sorted.push_back({ k, v });
    std::sort(sorted.begin(), sorted.end(),
        [](const SiteEntry& a, const SiteEntry& b) {
            return a.site.total_bytes > b.site.total_bytes;
        });
    first = true;
    int n = 0;
    for (const auto& e : sorted) {
        if (n++ >= cfg.top_allocs * 2) break;
        if (!first) f << ",\n";
        f << "    {\"count\": " << e.site.count
            << ", \"total_bytes\": " << e.site.total_bytes
            << ", \"stack\": [";
        for (int i = 0; i < e.site.stack_depth; ++i) {
            if (i) f << ", ";
            f << "\"0x" << std::hex << e.site.stack[i] << std::dec << "\"";
        }
        f << "]}";
        first = false;
    }
    f << "\n  ]\n}\n";

    std::printf("\n[memtrace] JSON report written to: %s\n", cfg.output_file.c_str());
}

static void print_final_report(const Config& cfg, const ipc::SharedHeader* hdr, HANDLE target_proc = nullptr) {
    std::printf("\n%s%s================== memtrace FINAL REPORT ==================%s\n",
        col::b(), col::cy(), col::r());
    std::printf("  target PID          : %lu\n", (unsigned long)hdr->target_pid);
    std::printf("  total allocations   : %llu\n", (unsigned long long)g_state.total_alloc_count);
    std::printf("  total frees         : %llu\n", (unsigned long long)g_state.total_free_count);
    std::printf("  total alloc bytes   : %s\n", human_bytes(g_state.total_alloc_bytes).c_str());
    std::printf("  peak live bytes     : %s\n", human_bytes(g_state.peak_bytes).c_str());
    std::printf("  live at exit        : %llu allocs, %s\n",
        (unsigned long long)g_state.live.size(),
        human_bytes(g_state.current_bytes).c_str());
    std::printf("  dropped events      : %llu\n", (unsigned long long)hdr->dropped_events);

    static std::unordered_map<std::uint64_t, std::uint64_t> baseline_bytes;
    static bool baseline_initialized = false;

    if (!baseline_initialized && !g_state.sites.empty()) {
        for (const auto& pair : g_state.sites) {
            baseline_bytes[pair.first] = pair.second.total_bytes;
        }
        baseline_initialized = true;
    }

    int growing_sites = 0, stable_sites = 0, suspect_sites = 0;
    std::uint64_t leak_bytes = 0, stable_bytes = 0, suspect_bytes = 0;

    struct LeakCandidate {
        std::uint64_t key;
        const AllocSite* site;
    };
    std::vector<LeakCandidate> leak_candidates;

    struct LargeSite {
        std::uint64_t key;
        const AllocSite* site;
    };
    std::vector<LargeSite> all_large_sites;

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);

        for (const auto& pair : g_state.sites) {
            if (pair.second.total_bytes > 1024 * 1024) { /* >1MB */
                LargeSite ls;
                ls.key = pair.first;
                ls.site = &pair.second;
                all_large_sites.push_back(ls);
            }
        }

        std::sort(all_large_sites.begin(), all_large_sites.end(),
            [](const LargeSite& a, const LargeSite& b) {
                return a.site->total_bytes > b.site->total_bytes;
            });

        for (const auto& pair : g_state.sites) {
            auto baseline_it = baseline_bytes.find(pair.first);

            if (baseline_it != baseline_bytes.end()) {
                uint64_t baseline = baseline_it->second;

                if (pair.second.total_bytes > baseline) {
                    uint64_t growth = pair.second.total_bytes - baseline;
                    double growth_pct = (growth * 100.0) / baseline;

                    /* consider it a leak if growth > 10 % AND > 100KB OR growth > 1MB */
                    bool is_leak = false;
                    if (growth_pct > 10.0 && growth > 1024 * 100) {
                        is_leak = true;
                    }
                    else if (growth > 1024 * 1024) {
                        is_leak = true;
                    }

                    if (is_leak) {
                        growing_sites++;
                        leak_bytes += growth;
                        if (pair.second.total_bytes > 1024 * 1024) {
                            LeakCandidate lc;
                            lc.key = pair.first;
                            lc.site = &pair.second;
                            leak_candidates.push_back(lc);
                        }
                    }
                    else if (growth_pct > 0) {
                        suspect_sites++;
                        suspect_bytes += growth;
                    }
                    else {
                        stable_sites++;
                        stable_bytes += pair.second.total_bytes;
                    }
                }
                else {
                    stable_sites++;
                    stable_bytes += pair.second.total_bytes;
                }
            }
            else {
                if (pair.second.total_bytes > 1024 * 100) {
                    growing_sites++;
                    leak_bytes += pair.second.total_bytes;
                    if (pair.second.total_bytes > 1024 * 1024) {
                        LeakCandidate lc;
                        lc.key = pair.first;
                        lc.site = &pair.second;
                        leak_candidates.push_back(lc);
                    }
                }
                else {
                    stable_sites++;
                    stable_bytes += pair.second.total_bytes;
                }
                baseline_bytes[pair.first] = pair.second.total_bytes;
            }
        }
    }

    if (growing_sites == 0 && g_state.current_bytes > 100 * 1024 * 1024) {
        std::printf("\n  %s%s[!] Large live memory detected (%s)%s\n",
            col::b(), col::rd(), human_bytes(g_state.current_bytes).c_str(), col::r());
        growing_sites = 1;
        leak_bytes = g_state.current_bytes;

        for (const auto& ls : all_large_sites) {
            LeakCandidate lc;
            lc.key = ls.key;
            lc.site = ls.site;
            leak_candidates.push_back(lc);
        }
    }

    if (growing_sites > 0) {
        std::printf("\n  %s%s[!] MEMORY LEAKS DETECTED%s\n", col::b(), col::rd(), col::r());
        std::printf("  %s  ├─ %d actively growing allocation sites%s\n", col::rd(), growing_sites, col::r());
        std::printf("  %s  └─ Total leaked bytes: %s (%.2f%% of live memory)%s\n",
            col::rd(), human_bytes(leak_bytes).c_str(),
            (leak_bytes * 100.0 / std::max(g_state.current_bytes, 1ULL)), col::r());

        if (cfg.show_stack && target_proc && !leak_candidates.empty()) {
            std::printf("\n  %s%sTop leak candidates:%s\n", col::b(), col::yw(), col::r());
            int shown = 0;
            for (const auto& cand : leak_candidates) {
                if (shown++ >= 10) break;
                const AllocSite* site = cand.site;
                double pct_of_live = (site->total_bytes * 100.0) / std::max(g_state.current_bytes, 1ULL);
                std::printf("    %s- %s (%llu allocations, %.1f%% of live)%s\n",
                    col::rd(), human_bytes(site->total_bytes).c_str(),
                    (unsigned long long)site->count, pct_of_live, col::r());

                int printed = 0;
                for (int i = 0; i < std::min<int>(site->stack_depth, 15) && printed < 8; ++i) {
                    if (site->stack[i] == 0) continue;
                    std::string sym = resolve_symbol(target_proc, site->stack[i]);
                    if (sym.length() > 90) sym = sym.substr(0, 87) + "...";
                    std::printf("      %s└─ %s%s\n", col::dm(), sym.c_str(), col::r());
                    printed++;
                }
            }
        }
    }
    else if (suspect_sites > 0) {
        std::printf("\n  %s%sSuspicious allocations (minor growth):%s\n", col::b(), col::yw(), col::r());
        std::printf("  %s  ├─ %d sites with minor growth%s\n", col::yw(), suspect_sites, col::r());
        std::printf("  %s  └─ Total suspect bytes: %s%s\n", col::yw(), human_bytes(suspect_bytes).c_str(), col::r());
    }

    if (stable_sites > 0 && stable_bytes > 0) {
        std::printf("\n  %s%sStable allocations (likely caches/pools):%s\n", col::b(), col::gn(), col::r());
        std::printf("  %s  ├─ %d stable allocation sites%s\n", col::gn(), stable_sites, col::r());
        std::printf("  %s  └─ Total stable memory: %s%s\n", col::gn(), human_bytes(stable_bytes).c_str(), col::r());
    }

    if (growing_sites > 0) {
        std::printf("\n  %s%sVERDICT: Memory leaks confirmed - %d leaking site(s) (%s)%s\n",
            col::b(), col::rd(), growing_sites, human_bytes(leak_bytes).c_str(), col::r());
    }
    else if (g_state.current_bytes > 100 * 1024 * 1024) {
        std::printf("\n  %s%sVERDICT: High memory usage (%s) with no growth detected - likely large cache%s\n",
            col::b(), col::yw(), human_bytes(g_state.current_bytes).c_str(), col::r());
    }
    else if (g_state.current_bytes == 0) {
        std::printf("\n  %s%sVERDICT: CLEAN - All memory freed at exit%s\n",
            col::b(), col::gn(), col::r());
    }
    else {
        std::printf("\n  %s%sVERDICT: CLEAN - No memory leaks detected%s\n",
            col::b(), col::gn(), col::r());
    }

    if (cfg.dump_all_stacks && target_proc && (growing_sites > 0 || g_state.current_bytes > 50 * 1024 * 1024)) {
        std::printf("\n%s%s=== Stack traces for large allocation sites ===%s\n",
            col::b(), col::cy(), col::r());
        int idx = 0;

        std::vector<LargeSite> sorted_sites;
        for (const auto& pair : g_state.sites) {
            if (pair.second.total_bytes > 100 * 1024) {
                LargeSite ls;
                ls.key = pair.first;
                ls.site = &pair.second;
                sorted_sites.push_back(ls);
            }
        }
        std::sort(sorted_sites.begin(), sorted_sites.end(),
            [](const LargeSite& a, const LargeSite& b) {
                return a.site->total_bytes > b.site->total_bytes;
            });

        for (const auto& ls : sorted_sites) {
            if (idx++ >= 20) break;
            const AllocSite* site = ls.site;
            double pct = (site->total_bytes * 100.0) / std::max(g_state.current_bytes, 1ULL);
            std::printf("\n%sSite #%d: %s (%llu allocs, %.1f%% of live)%s\n",
                col::yw(), idx, human_bytes(site->total_bytes).c_str(),
                (unsigned long long)site->count, pct, col::r());

            for (int i = 0; i < std::min<int>(site->stack_depth, 20); ++i) {
                if (site->stack[i] == 0) continue;
                std::string sym = resolve_symbol(target_proc, site->stack[i]);
                if (sym.length() > 100) sym = sym.substr(0, 97) + "...";

                bool is_last = (i == std::min<int>(site->stack_depth, 20) - 1) ||
                    (i + 1 < std::min<int>(site->stack_depth, 20) && site->stack[i + 1] == 0);

                const char* prefix = is_last ? "  └─ " : "  ├─ ";

                const char* color;
                if (i == 0) {
                    color = col::cy();
                }
                else {
                    color = col::dm();
                }

                std::printf("%s%s[%d] %s%s\n", color, prefix, i, sym.c_str(), col::r());
            }
        }
    }

    if (!cfg.output_file.empty() && hdr)
        write_json_report(cfg, hdr);
}


/* 1.0v of inject dll (to be improved) */
static bool inject_dll(HANDLE proc, const std::string& dll_path) {
    const std::size_t path_len = dll_path.size() + 1;

    void* remote_str = VirtualAllocEx(proc, nullptr, path_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_str) {
        std::fprintf(stderr, "[memtrace] VirtualAllocEx failed: %lu\n", GetLastError());
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, remote_str, dll_path.c_str(), path_len, &written)
        || written != path_len)
    {
        std::fprintf(stderr, "[memtrace] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE);
        return false;
    }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE); return false; }

    auto* load_lib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(k32, "LoadLibraryA"));
    if (!load_lib) { VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE); return false; }

    HANDLE remote_thread = CreateRemoteThread(
        proc, nullptr, 0, load_lib, remote_str, 0, nullptr);
    if (!remote_thread) {
        std::fprintf(stderr, "[memtrace] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(remote_thread, 10000);
    CloseHandle(remote_thread);
    VirtualFreeEx(proc, remote_str, 0, MEM_RELEASE);
    return true;
}

static void print_usage(const char* argv0) {
    std::printf(
        "usage: %s --pid <PID> | --launch <exe.exe> [options]\n\n"
        "options:\n"
        "  --pid <N>                 attach to running process by PID\n"
        "  --launch <exe>            launch and instrument a new process\n"
        "  --args \"<args>\"           arguments for launched process\n"
        "  --report-interval <ms>    dashboard refresh rate (default: 1000)\n"
        "  --top-allocs <N>          top N sites shown (default: 10)\n"
        "  --output <file.json>      write JSON report on exit\n"
        "  --stack                   resolve stack symbols (requires .pdb)\n"
        "  --dump-stacks             dump full stack traces for large allocations\n"
        "  --threshold <bytes>       ignore allocs smaller than N bytes\n"
        "  --duration <seconds>      auto stop after N seconds (0=forever)\n"
        "  --no-color                disable ANSI color output\n"
        "  --quiet                   skip live dashboard\n\n"
        "examples:\n"
        "  %s --pid 1234\n"
        "  %s --launch notepad.exe --output report.json --stack\n"
        "  %s --pid 5678 --top-allocs 20 --threshold 4096 --duration 60\n",
        argv0, argv0, argv0, argv0);
}

static bool parse_args(int argc, char** argv, Config& cfg) {
    if (argc < 2) { print_usage(argv[0]); return false; }
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 < argc) return argv[++i];
            std::fprintf(stderr, "missing value for %s\n", a.c_str());
            return "";
            };
        if (a == "--pid")                  cfg.pid = std::stoul(next());
        else if (a == "--launch")          cfg.launch_exe = next();
        else if (a == "--args")            cfg.launch_args = next();
        else if (a == "--report-interval") cfg.report_interval_ms = std::stoul(next());
        else if (a == "--top-allocs")      cfg.top_allocs = std::stoi(next());
        else if (a == "--output")          cfg.output_file = next();
        else if (a == "--stack")           cfg.show_stack = true;
        else if (a == "--dump-stacks")     cfg.dump_all_stacks = true;
        else if (a == "--threshold")       cfg.threshold_bytes = std::stoull(next());
        else if (a == "--duration")        cfg.duration_s = std::stoi(next());
        else if (a == "--no-color")        cfg.no_color = true;
        else if (a == "--quiet")           cfg.quiet = true;
        else if (a == "--help" || a == "-h") { print_usage(argv[0]); return false; }
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); return false; }
    }
    if (cfg.pid == 0 && cfg.launch_exe.empty()) {
        std::fprintf(stderr, "error: specify --pid or --launch\n");
        return false;
    }
    return true;
}

static std::atomic<bool> g_stop{ false };

static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        g_stop.store(true);
        return TRUE;
    }
    return FALSE;
}

static std::string find_payload_dll() {
    char exe_path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    std::string dir = exe_path;
    auto pos = dir.find_last_of("\\/");
    if (pos != std::string::npos) dir = dir.substr(0, pos + 1);
    return dir + "payload-dll.dll";
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    Config cfg;
    if (!parse_args(argc, argv, cfg)) return 1;

    col::enabled = !cfg.no_color;

    /* enable virtual terminal processing for ANSI on Windows 10+ */
    if (col::enabled) {
        HANDLE con = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD  mode = 0;
        GetConsoleMode(con, &mode);
        SetConsoleMode(con, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    cfg.dll_path = find_payload_dll();
    if (GetFileAttributesA(cfg.dll_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr,
            "[memtrace] ERROR: payload-dll.dll not found at: %s\n"
            "  Place payload-dll.dll in the same directory as memtrace-runtime.exe\n",
            cfg.dll_path.c_str());
        return 1;
    }

    HANDLE target_proc = nullptr;
    HANDLE target_main_thread = nullptr;
    bool   we_launched = false;

    if (!cfg.launch_exe.empty()) {
        std::string cmd = "\"" + cfg.launch_exe + "\"";
        if (!cfg.launch_args.empty()) cmd += " " + cfg.launch_args;

        STARTUPINFOA        si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessA(nullptr, &cmd[0], nullptr, nullptr, FALSE,
            CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        {
            std::fprintf(stderr, "[memtrace] Failed to launch %s: %lu\n",
                cfg.launch_exe.c_str(), GetLastError());
            return 1;
        }
        cfg.pid = pi.dwProcessId;
        target_proc = pi.hProcess;
        target_main_thread = pi.hThread;
        we_launched = true;
        std::printf("[memtrace] Launched '%s' as PID %lu\n",
            cfg.launch_exe.c_str(), (unsigned long)cfg.pid);
    }
    else {
        target_proc = OpenProcess(
            PROCESS_ALL_ACCESS, FALSE, cfg.pid);
        if (!target_proc) {
            std::fprintf(stderr,
                "[memtrace] Cannot open PID %lu: %lu\n"
                "  Tip: run memtrace-runtime.exe as Administrator.\n",
                (unsigned long)cfg.pid, GetLastError());
            return 1;
        }
        std::printf("[memtrace] Attached to PID %lu\n", (unsigned long)cfg.pid);
    }

    char event_name[128] = {};
    ipc::make_ready_event_name(event_name, sizeof(event_name), cfg.pid);
    HANDLE ready_event = CreateEventA(nullptr, TRUE, FALSE, event_name);

    /* inject our payload dll */
    std::printf("[memtrace] Injecting payload-dll.dll into PID %lu ...\n",
        (unsigned long)cfg.pid);
    if (!inject_dll(target_proc, cfg.dll_path)) {
        std::fprintf(stderr, "[memtrace] Injection failed.\n");
        CloseHandle(target_proc);
        return 1;
    }

    if (we_launched && target_main_thread) {
        ResumeThread(target_main_thread);
        CloseHandle(target_main_thread);
        target_main_thread = nullptr;
    }

    /* waiting for payload to signal ready */
    std::printf("[memtrace] waiting for hooks\n");
    DWORD wait_result = WaitForSingleObject(ready_event, 8000);
    if (wait_result != WAIT_OBJECT_0) {
        std::fprintf(stderr, "[memtrace] payload did not signal ready (timeout)\n");
        std::fprintf(stderr, "[memtrace] payload dll (probably) didnt inject or platform mismatch\n");
        return 1;
    }
    CloseHandle(ready_event);

    char shm_name[128] = {};
    ipc::make_shm_name(shm_name, sizeof(shm_name), cfg.pid);
    HANDLE shm = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, shm_name);
    if (!shm) {
        std::fprintf(stderr, "[memtrace] could not open shared memory: %lu\n", GetLastError());
        CloseHandle(target_proc);
        return 1;
    }
    void* view = MapViewOfFile(shm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!view) {
        std::fprintf(stderr, "[memtrace] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(shm); CloseHandle(target_proc);
        return 1;
    }

    auto* hdr = reinterpret_cast<ipc::SharedHeader*>(view);
    auto* ring = reinterpret_cast<ipc::AllocEvent*>(
        reinterpret_cast<std::uint8_t*>(view) + sizeof(ipc::SharedHeader));

    if (hdr->magic != ipc::kMagic) {
        std::fprintf(stderr, "[memtrace] shared memory magic mismatch\n");
        UnmapViewOfFile(view); CloseHandle(shm); CloseHandle(target_proc);
        return 1;
    }

    InterlockedExchange(&hdr->host_attached, 1);

    /* symbol resolution */
    if (cfg.show_stack) {
        SymSetOptions(
            SYMOPT_UNDNAME |
            SYMOPT_DEFERRED_LOADS |
            SYMOPT_LOAD_LINES |
            SYMOPT_INCLUDE_32BIT_MODULES);
        SymInitialize(target_proc, nullptr, TRUE);
    }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    std::printf("[memtrace] hooks placed, starting to stream\n\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto start_time = std::chrono::steady_clock::now();
    auto last_report = start_time;
    std::uint64_t read_seq = 0;

    while (!g_stop.load()) {
        DWORD exit_code = STILL_ACTIVE;
        if (!GetExitCodeProcess(target_proc, &exit_code) || exit_code != STILL_ACTIVE) {
            std::printf("\n[memtrace] target process exited (code %lu)\n",
                (unsigned long)exit_code);
            break;
        }

        std::uint64_t write_pos = hdr->write_pos;

        while (read_seq < write_pos) {
            const ipc::AllocEvent& ev =
                ring[read_seq & ipc::kRingMask];

            if (ev.seq != read_seq)
                break;

            process_event(ev, cfg);
            ++read_seq;
        }

        hdr->read_pos = read_seq;

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start_time).count();

        if (!cfg.quiet &&
            std::chrono::duration_cast<std::chrono::milliseconds>(now - last_report).count()
            >= static_cast<long long>(cfg.report_interval_ms))
        {
            print_dashboard(cfg, target_proc, hdr, elapsed);
            last_report = now;
        }

        if (cfg.duration_s > 0 && elapsed >= cfg.duration_s) {
            std::printf("\n[memtrace] duration limit reached (%d s)\n", cfg.duration_s);
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    /* cleanup */

    InterlockedExchange(&hdr->request_unload, 1);
    InterlockedExchange(&hdr->host_attached, 0);

    if (cfg.show_stack) SymCleanup(target_proc);

    print_final_report(cfg, hdr, target_proc);

    UnmapViewOfFile(view);
    CloseHandle(shm);
    CloseHandle(target_proc);
    return 0;
}