#define _GNU_SOURCE 1

#include "dexhelper_bypass.h"

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <ctype.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG  "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/* ── types ─────────────────────────────────────────────────────────────── */
typedef int (*pthread_create_fn)(pthread_t *, const pthread_attr_t *,
                                 void *(*)(void *), void *);
typedef int (*clone_raw_fn)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
                            uintptr_t, uintptr_t, uintptr_t, uintptr_t);

/* ── file-scope state ───────────────────────────────────────────────────── */
static volatile int           g_enabled    = 0;
static volatile int           g_hooked     = 0;
static pthread_create_fn      g_orig_pth   = NULL;   /* real libc pthread_create */
static clone_raw_fn           g_orig_clone = NULL;   /* real libc clone */
static volatile uintptr_t     g_dex_base   = 0;
static volatile size_t        g_dex_size   = 0;
static volatile int           g_clone_log_budget = 12;
static volatile int           g_pthread_log_budget = 12;
static volatile int           g_known_offsets_patched = 0;
static volatile int           g_find_log_budget = 4;

/* ── helpers ─────────────────────────────────────────────────────────────── */

static int ascii_contains_nocase(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;

    size_t needle_len = strlen(needle);
    for (const char *p = haystack; *p; ++p) {
        size_t i = 0;
        while (i < needle_len && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            ++i;
        }
        if (i == needle_len) return 1;
    }
    return 0;
}

static int path_matches_dexhelper(const char *path) {
    return ascii_contains_nocase(path, "dexhelper");
}

static int path_is_libc(const char *path) {
    return ascii_contains_nocase(path, "libc.so");
}

typedef struct dexhelper_module_info {
    uintptr_t base;
    size_t size;
    char path[256];
} dexhelper_module_info_t;

static int phdr_find_dexhelper_cb(struct dl_phdr_info *info, size_t info_size, void *data) {
    (void)info_size;
    dexhelper_module_info_t *out = (dexhelper_module_info_t *)data;
    const char *name = (info && info->dlpi_name) ? info->dlpi_name : NULL;
    if (!path_matches_dexhelper(name)) return 0;

    uintptr_t hi = 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t end = (uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr + (uintptr_t)ph->p_memsz;
        if (end > hi) hi = end;
    }

    out->base = (uintptr_t)info->dlpi_addr;
    out->size = hi > out->base ? (size_t)(hi - out->base) : 0;
    if (name) {
        strncpy(out->path, name, sizeof(out->path) - 1);
        out->path[sizeof(out->path) - 1] = '\0';
    } else {
        strncpy(out->path, "<phdr>", sizeof(out->path) - 1);
        out->path[sizeof(out->path) - 1] = '\0';
    }
    return 1;
}

static int phdr_find_dexhelper_module(uintptr_t *base, size_t *size, char *path_out, size_t path_len) {
    dexhelper_module_info_t info;
    memset(&info, 0, sizeof(info));
    info.path[0] = '\0';

    dl_iterate_phdr(phdr_find_dexhelper_cb, &info);
    if (!info.base) return 0;

    if (base) *base = info.base;
    if (size) *size = info.size;
    if (path_out && path_len > 0) {
        strncpy(path_out, info.path[0] ? info.path : "<phdr>", path_len - 1);
        path_out[path_len - 1] = '\0';
    }
    return 1;
}

/* Find the contiguous virtual-address range of a DexHelper-like library in maps. */
static void maps_find_dexhelper_module(uintptr_t *base, size_t *size) {
    *base = 0; *size = 0;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[512];
    uintptr_t lo = 0, hi = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!path_matches_dexhelper(line)) continue;
        uintptr_t s = 0, e = 0;
        if (sscanf(line, "%lx-%lx", &s, &e) != 2) continue;
        if (!lo || s < lo) lo = s;
        if (e > hi) hi = e;
    }
    fclose(fp);
    if (lo && hi > lo) { *base = lo; *size = hi - lo; }
}

static int maps_find_module_for_addr(uintptr_t addr, uintptr_t *base_out,
                                     size_t *size_out, char *path_out, size_t path_len) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    int found = 0;
    char line[512];
    if (base_out) *base_out = 0;
    if (size_out) *size_out = 0;
    if (path_out && path_len > 0) path_out[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, file_off = 0, inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255[^\n]",
                       &start, &end, perms, &file_off, dev, &inode, path);
        if (addr < (uintptr_t)start || addr >= (uintptr_t)end) continue;

        if (base_out) *base_out = (uintptr_t)start - (uintptr_t)file_off;
        if (size_out) *size_out = (size_t)((uintptr_t)end - ((uintptr_t)start - (uintptr_t)file_off));
        if (path_out && path_len > 0) {
            if (n >= 7) {
                const char *p = path;
                while (*p == ' ') ++p;
                strncpy(path_out, p, path_len - 1);
                path_out[path_len - 1] = '\0';
            } else {
                strncpy(path_out, "<anonymous>", path_len - 1);
                path_out[path_len - 1] = '\0';
            }
        }
        found = 1;
        break;
    }

    fclose(fp);
    return found;
}

static int maps_addr_is_readable(uintptr_t addr, size_t len) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    int readable = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3) continue;
        if (perms[0] != 'r') continue;
        if (addr >= (uintptr_t)start && (addr + len) <= (uintptr_t)end) {
            readable = 1;
            break;
        }
    }

    fclose(fp);
    return readable;
}

static void refresh_dexhelper_range(void) {
    uintptr_t base = 0;
    size_t size = 0;
    if (!phdr_find_dexhelper_module(&base, &size, NULL, 0)) {
        maps_find_dexhelper_module(&base, &size);
    }
    if (!base) return;
    g_dex_base = base;
    g_dex_size = size;
}

static void log_addr_module(const char *label, uintptr_t addr) {
    uintptr_t base = 0;
    size_t size = 0;
    char path[256];
    path[0] = '\0';

    if (!addr || !maps_find_module_for_addr(addr, &base, &size, path, sizeof(path))) {
        LOGI("%s: addr=0x%lx module=<unknown>", label, (unsigned long)addr);
        return;
    }

    LOGI("%s: addr=0x%lx module=%s off=0x%lx",
         label,
         (unsigned long)addr,
         path[0] ? path : "<anonymous>",
         (unsigned long)(addr - base));
}

static int nop_64(uintptr_t addr) {
#if defined(__aarch64__)
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page = addr & ~((uintptr_t)page_size - 1);
    uint32_t *insn = (uint32_t *)addr;
    const uint32_t ret_insn = 0xD65F03C0U; /* RET */

    if (mprotect((void *)page, (size_t)page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGW("mprotect(RWX) failed for code @ 0x%lx", (unsigned long)addr);
        return -1;
    }

    if (*insn != ret_insn) {
        *insn = ret_insn;
        __builtin___clear_cache((char *)page, (char *)(page + (uintptr_t)page_size));
    }

    mprotect((void *)page, (size_t)page_size, PROT_READ | PROT_EXEC);
    return 0;
#else
    (void)addr;
    return -1;
#endif
}

/* NOP thread function – replaces the detection thread's start_routine. */
static void *nop_thread_fn(void *arg) { (void)arg; return NULL; }

static void patch_known_clone_entries(uintptr_t base, size_t size) {
    static const uintptr_t known_offsets[] = {
        0x52cc0, 0x561d0, 0x5ded4, 0x5e410, 0x69470
    };

    if (!base || g_known_offsets_patched) return;

    int patched = 0;
    for (size_t i = 0; i < sizeof(known_offsets) / sizeof(known_offsets[0]); ++i) {
        uintptr_t off = known_offsets[i];
        if (size && off >= (uintptr_t)size) continue;
        if (nop_64(base + off) == 0) {
            LOGI("DexHelper known clone entry nopped: fn=0x%lx off=0x%lx",
                 (unsigned long)(base + off),
                 (unsigned long)off);
            patched = 1;
        }
    }

    if (patched) {
        g_known_offsets_patched = 1;
    }
}

/* ── hook ────────────────────────────────────────────────────────────────── */

static int hooked_pthread_create(pthread_t *t, const pthread_attr_t *attr,
                                  void *(*fn)(void *), void *arg) {
    if (g_enabled && fn) {
        if (!g_dex_base) refresh_dexhelper_range();
        uintptr_t f = (uintptr_t)fn;
        if (g_pthread_log_budget > 0) {
            g_pthread_log_budget--;
            log_addr_module("pthread_create start_routine", f);
        }
        if (f >= g_dex_base && f < g_dex_base + g_dex_size) {
            LOGI("DexHelper detection thread blocked: fn=0x%lx off=0x%lx",
                 (unsigned long)f, (unsigned long)(f - g_dex_base));
            fn = nop_thread_fn;
        }
    }
    return g_orig_pth(t, attr, fn, arg);
}

static int hooked_clone(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                        uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t arg7) {
    (void)arg0; (void)arg1; (void)arg2;
    (void)arg4; (void)arg5; (void)arg6; (void)arg7;

    if (g_enabled && arg3) {
        if (g_clone_log_budget > 0) {
            static const int candidate_offsets[] = {80, 88, 96, 104, 112, 120, 128};
            g_clone_log_budget--;
            LOGI("clone sample: arg0=0x%lx arg1=0x%lx arg2=0x%lx arg3=0x%lx",
                 (unsigned long)arg0, (unsigned long)arg1,
                 (unsigned long)arg2, (unsigned long)arg3);
            log_addr_module("clone arg0", arg0);
            for (size_t i = 0; i < sizeof(candidate_offsets) / sizeof(candidate_offsets[0]); ++i) {
                uintptr_t slot = arg3 + (uintptr_t)candidate_offsets[i];
                if (!maps_addr_is_readable(slot, sizeof(uintptr_t))) continue;
                uintptr_t candidate = *(uintptr_t *)slot;
                char label[64];
                snprintf(label, sizeof(label), "clone arg3+%d", candidate_offsets[i]);
                log_addr_module(label, candidate);
            }
        }

        if (maps_addr_is_readable(arg3 + 96, sizeof(uintptr_t))) {
            uintptr_t entry = *(uintptr_t *)(arg3 + 96);
            uintptr_t base = 0;
            size_t size = 0;
            char path[256];
            path[0] = '\0';

            if (entry && maps_find_module_for_addr(entry, &base, &size, path, sizeof(path)) &&
                path_matches_dexhelper(path) && !path_is_libc(path)) {
                g_dex_base = base;
                g_dex_size = size;
                if (nop_64(entry) == 0) {
                    LOGI("DexHelper clone entry nopped: module=%s fn=0x%lx off=0x%lx",
                         path,
                         (unsigned long)entry,
                         (unsigned long)(entry - base));
                }
            }
        }
    }

    if (!g_orig_clone) {
        return -1;
    }
    return g_orig_clone(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

/* ── ELF GOT patcher ─────────────────────────────────────────────────────── */

/*
 * Patch the GOT entry for `sym_name` inside the ELF loaded at `base`.
 * Scans both PLT relocations and regular RELA relocations because packers
 * often resolve `clone` via non-PLT slots.
 *
 * Returns 0 on success, -1 if symbol not found or ELF invalid.
 */
static int patch_got(uintptr_t base, const char *sym_name,
                     void *new_fn, void **old_fn_out) {
    if (!base) return -1;

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
    if (memcmp(eh->e_ident, "\x7f" "ELF", 4) != 0) return -1;

    /* Compute load bias from the first PT_LOAD with p_offset == 0. */
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(base + eh->e_phoff);
    uintptr_t load_bias = base;   /* default: assume first LOAD p_vaddr == 0 */
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && ph[i].p_offset == 0) {
            load_bias = base - (uintptr_t)ph[i].p_vaddr;
            break;
        }
    }

    /* Locate the dynamic segment. */
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(load_bias + ph[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return -1;

    /* Parse dynamic section for relocation tables + symbol/string tables. */
    const Elf64_Rela *jmprel  = NULL;  size_t jmprel_cnt = 0;
    const Elf64_Rela *rela    = NULL;  size_t rela_cnt = 0;
    const Elf64_Sym  *symtab  = NULL;
    const char       *strtab  = NULL;

    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch ((int)d->d_tag) {
            case DT_JMPREL:
                jmprel = (const Elf64_Rela *)(load_bias + d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                jmprel_cnt = d->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_RELA:
                rela = (const Elf64_Rela *)(load_bias + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                rela_cnt = d->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_SYMTAB:
                symtab = (const Elf64_Sym *)(load_bias + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char *)(load_bias + d->d_un.d_ptr);
                break;
        }
    }
    if (!symtab || !strtab) return -1;

    const Elf64_Rela *tables[] = { jmprel, rela };
    const size_t counts[] = { jmprel_cnt, rela_cnt };
    for (size_t table_idx = 0; table_idx < sizeof(tables) / sizeof(tables[0]); ++table_idx) {
        const Elf64_Rela *table = tables[table_idx];
        size_t count = counts[table_idx];
        if (!table || count == 0) continue;

        for (size_t i = 0; i < count; i++) {
            uint32_t si = (uint32_t)ELF64_R_SYM(table[i].r_info);
            const char *name = strtab + symtab[si].st_name;
            if (strcmp(name, sym_name) != 0) continue;

            void **got = (void **)(load_bias + table[i].r_offset);

            /* Make the page writable, patch, restore. */
            long pg = sysconf(_SC_PAGE_SIZE);
            void *pg_addr = (void *)((uintptr_t)got & ~(uintptr_t)(pg - 1));
            if (mprotect(pg_addr, (size_t)pg, PROT_READ | PROT_WRITE) != 0) {
                LOGW("mprotect(RW) failed for GOT @ %p", (void *)got);
                return -1;
            }
            if (old_fn_out) *old_fn_out = *got;
            *got = new_fn;
            mprotect(pg_addr, (size_t)pg, PROT_READ);

            return 0;   /* success */
        }
    }
    return -1;   /* symbol not found */
}

/* ── install logic ───────────────────────────────────────────────────────── */

static void try_install_now(void) {
    uintptr_t base = 0;
    size_t sz = 0;
    char path[256];
    path[0] = '\0';
    int via_phdr = phdr_find_dexhelper_module(&base, &sz, path, sizeof(path));
    if (!via_phdr) {
        maps_find_dexhelper_module(&base, &sz);
        if (base) {
            strncpy(path, "<maps>", sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
        }
    }
    if (!base) return;

    /* Remember the module range so the hook can filter by address. */
    g_dex_base = base;
    g_dex_size = sz;
    LOGI("DexHelper module found: base=0x%lx size=0x%lx source=%s",
         (unsigned long)base, (unsigned long)sz,
         path[0] ? path : (via_phdr ? "<phdr>" : "<maps>"));

    patch_known_clone_entries(base, sz);

    if (g_hooked) return;

    int patched = 0;
    void *old = NULL;
    if (patch_got(base, "pthread_create", (void *)hooked_pthread_create, &old) == 0) {
        if (old && old != (void *)hooked_pthread_create) {
            g_orig_pth = (pthread_create_fn)old;
        }
        LOGI("DexHelper pthread_create GOT patched");
        patched = 1;
    }

    old = NULL;
    if (patch_got(base, "clone", (void *)hooked_clone, &old) == 0) {
        if (old && old != (void *)hooked_clone) {
            g_orig_clone = (clone_raw_fn)old;
        }
        LOGI("DexHelper clone GOT patched");
        patched = 1;
    }

    old = NULL;
    if (patch_got(base, "__clone", (void *)hooked_clone, &old) == 0) {
        if (old && old != (void *)hooked_clone) {
            g_orig_clone = (clone_raw_fn)old;
        }
        LOGI("DexHelper __clone GOT patched");
        patched = 1;
    }

    if (patched) {
        g_hooked = 1;
    } else {
        LOGW("DexHelper GOT patch failed for pthread_create/clone");
    }
}

/* Background thread: polls every 5 ms at startup, then keeps watching at
 * a lower rate because some packers load DexHelper well after Application init. */
static void *poll_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 600 && g_enabled && !g_hooked; i++) {
        try_install_now();
        if (g_hooked) break;
        usleep(5000);   /* 5 ms */
    }

    for (int i = 0; i < 270 && g_enabled && !g_hooked; i++) {
        try_install_now();
        if (g_hooked) break;
        usleep(100000); /* 100 ms, ~27 s */
    }

    if (!g_hooked && g_enabled) {
        LOGW("DexHelper module not found after polling, bypass inactive");
    }
    return NULL;
}

/* ── public API ──────────────────────────────────────────────────────────── */

void dexhelper_bypass_set_enabled(int enabled) {
    g_enabled = enabled;
    LOGI("DexHelper thread bypass: %s", enabled ? "ON" : "OFF");

    if (!enabled) {
        g_hooked = 0;
        g_dex_base = 0;
        g_dex_size = 0;
        g_clone_log_budget = 12;
        g_pthread_log_budget = 12;
        g_known_offsets_patched = 0;
        g_find_log_budget = 4;
        return;
    }

    /* Ensure we always have a safe fallback for g_orig_pth. */
    if (!g_orig_pth) {
        g_orig_pth = (pthread_create_fn)dlsym(RTLD_DEFAULT, "pthread_create");
    }
    if (!g_orig_clone) {
        g_orig_clone = (clone_raw_fn)dlsym(RTLD_DEFAULT, "clone");
        if (!g_orig_clone) {
            g_orig_clone = (clone_raw_fn)dlsym(RTLD_DEFAULT, "__clone");
        }
    }

    try_install_now();

    if (!g_hooked && g_orig_pth) {
        /* libDexHelper.so may not be loaded yet — start a watcher thread.
         * Use g_orig_pth (libc's real pthread_create) to avoid any reentrancy. */
        pthread_t wt;
        g_orig_pth(&wt, NULL, poll_thread, NULL);
        pthread_detach(wt);
        LOGI("DexHelper bypass watcher thread started");
    }
}

void dexhelper_bypass_try_patch_now(void) {
    uintptr_t base = 0;
    size_t size = 0;
    if (!phdr_find_dexhelper_module(&base, &size, NULL, 0) && !g_dex_base && g_find_log_budget > 0) {
        g_find_log_budget--;
        LOGW("DexHelper patch requested but module is not visible yet");
    }
    try_install_now();
}
