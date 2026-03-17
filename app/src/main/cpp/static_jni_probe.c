#define _GNU_SOURCE 1

#include "static_jni_probe.h"

#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <string.h>

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static volatile int probe_enabled = 0;
static volatile int probe_done = 0;
static volatile int probe_miss_logged = 0;

typedef struct {
    uintptr_t addr;
    uintptr_t module_base;
    char module_name[256];
} addr_lookup_t;

typedef struct {
    uintptr_t module_base;
    char module_name[256];
} gtcore_module_info_t;

static int module_name_contains_gtcore(const char *name) {
    return name && strstr(name, "libgtcore.so") != NULL;
}

static int phdr_find_module_for_addr_cb(struct dl_phdr_info *info, size_t info_size, void *data) {
    (void)info_size;
    addr_lookup_t *lookup = (addr_lookup_t *)data;
    if (!lookup) return 0;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;

        uintptr_t start = (uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr;
        uintptr_t end = start + (uintptr_t)ph->p_memsz;
        if (lookup->addr < start || lookup->addr >= end) continue;

        lookup->module_base = (uintptr_t)info->dlpi_addr;
        const char *name = (info && info->dlpi_name && *info->dlpi_name) ? info->dlpi_name : "<phdr>";
        strncpy(lookup->module_name, name, sizeof(lookup->module_name) - 1);
        lookup->module_name[sizeof(lookup->module_name) - 1] = '\0';
        return 1;
    }

    return 0;
}

static uintptr_t find_module_for_addr(uintptr_t addr, char *module_name, size_t module_len) {
    addr_lookup_t lookup;
    memset(&lookup, 0, sizeof(lookup));
    lookup.addr = addr;

    dl_iterate_phdr(phdr_find_module_for_addr_cb, &lookup);
    if (!lookup.module_base) return 0;

    if (module_name && module_len > 0) {
        strncpy(module_name,
                lookup.module_name[0] ? lookup.module_name : "<phdr>",
                module_len - 1);
        module_name[module_len - 1] = '\0';
    }
    return lookup.module_base;
}

static int phdr_find_gtcore_cb(struct dl_phdr_info *info, size_t info_size, void *data) {
    (void)info_size;
    gtcore_module_info_t *out = (gtcore_module_info_t *)data;
    const char *name = (info && info->dlpi_name) ? info->dlpi_name : NULL;
    if (!out || !module_name_contains_gtcore(name)) return 0;

    out->module_base = (uintptr_t)info->dlpi_addr;
    strncpy(out->module_name, (name && *name) ? name : "<phdr>", sizeof(out->module_name) - 1);
    out->module_name[sizeof(out->module_name) - 1] = '\0';
    return 1;
}

static int find_gtcore_loaded_path(char *out, size_t out_len) {
    if (!out || out_len == 0) return 0;
    out[0] = '\0';

    gtcore_module_info_t info;
    memset(&info, 0, sizeof(info));
    dl_iterate_phdr(phdr_find_gtcore_cb, &info);
    if (!info.module_name[0]) return 0;

    strncpy(out, info.module_name, out_len - 1);
    out[out_len - 1] = '\0';
    return 1;
}

static int gtcore_visible_to_loader(void) {
    gtcore_module_info_t info;
    memset(&info, 0, sizeof(info));
    dl_iterate_phdr(phdr_find_gtcore_cb, &info);
    return info.module_name[0] != '\0';
}

static void close_if_valid_handle(void *handle) {
    if (handle) {
        dlclose(handle);
    }
}

void static_jni_probe_set_enabled(int enabled) {
    probe_enabled = enabled ? 1 : 0;
    if (!probe_enabled) {
        probe_done = 0;
        probe_miss_logged = 0;
    }
}

void static_jni_probe_try_log(void) {
    if (!probe_enabled || probe_done) return;

    void *handle = dlopen("libgtcore.so", RTLD_NOW | RTLD_NOLOAD);
    char loaded_path[256];
    loaded_path[0] = '\0';

    if (!handle && find_gtcore_loaded_path(loaded_path, sizeof(loaded_path))) {
        handle = dlopen(loaded_path, RTLD_NOW | RTLD_NOLOAD);
        if (!handle) {
            handle = dlopen(loaded_path, RTLD_NOW);
        }
    }
    if (!handle) {
        if (gtcore_visible_to_loader() && !probe_miss_logged) {
            LOGI("StaticJNI probe: libgtcore visible via loader but dlopen handle is unavailable");
            probe_miss_logged = 1;
        }
        return;
    }

    const char *symbols[] = {
        "Java_com_geetest_core_Core_getData__Landroid_content_Context_2",
        "Java_com_geetest_core_Core_getData__Landroid_content_Context_2Lcom_geetest_core_GeeGuardConfiguration_2",
        "Java_com_geetest_core_C3326Core_getData__Landroid_content_Context_2",
        "Java_com_geetest_core_C3326Core_getData__Landroid_content_Context_2Lcom_geetest_core_GeeGuardConfiguration_2",
    };

    int hit = 0;
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        void *sym = dlsym(handle, symbols[i]);
        if (!sym) continue;

        uintptr_t fn = (uintptr_t)sym;
        char module_name[256];
        uintptr_t base = find_module_for_addr(fn, module_name, sizeof(module_name));
        if (!base) continue;
        if (!module_name_contains_gtcore(module_name)) {
            continue;
        }

        uintptr_t off = fn - base;
        LOGI("StaticJNI sym:%s module:%s module_base:0x%lx offset:0x%lx fn:0x%lx",
             symbols[i], module_name, (unsigned long)base, (unsigned long)off, (unsigned long)fn);
        hit++;
    }

    if (hit > 0) {
        probe_done = 1;
        probe_miss_logged = 0;
    } else if (!probe_miss_logged) {
        LOGI("StaticJNI probe: libgtcore loaded but target exported symbols not found");
        probe_miss_logged = 1;
    }

    close_if_valid_handle(handle);
}
