#include "static_jni_probe.h"

#include <android/log.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static volatile int probe_enabled = 0;
static volatile int probe_done = 0;
static volatile int probe_miss_logged = 0;

static int ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return 0;
    size_t slen = strlen(s);
    size_t tlen = strlen(suffix);
    if (slen < tlen) return 0;
    return strcmp(s + slen - tlen, suffix) == 0;
}

static uintptr_t find_module_for_addr(uintptr_t addr, char *module_name, size_t module_len) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    uintptr_t base = 0;
    char line[512];
    if (module_name && module_len > 0) module_name[0] = '\0';

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long start = 0, end = 0, file_off = 0, inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255[^\n]",
                       &start, &end, perms, &file_off, dev, &inode, path);
        if (addr < (uintptr_t)start || addr >= (uintptr_t)end) continue;

        base = (uintptr_t)start;
        if (module_name && module_len > 0) {
            if (n >= 7) {
                const char *p = path;
                while (*p == ' ') p++;
                strncpy(module_name, p, module_len - 1);
                module_name[module_len - 1] = '\0';
            } else {
                strncpy(module_name, "<anonymous>", module_len - 1);
                module_name[module_len - 1] = '\0';
            }
        }
        break;
    }

    fclose(fp);
    return base;
}

static int find_gtcore_mapped_path(char *out, size_t out_len) {
    if (!out || out_len == 0) return 0;
    out[0] = '\0';

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "libgtcore.so") == NULL) continue;

        unsigned long start = 0, end = 0, file_off = 0, inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255[^\n]",
                       &start, &end, perms, &file_off, dev, &inode, path);
        if (n < 7) continue;
        const char *p = path;
        while (*p == ' ') p++;
        strncpy(out, p, out_len - 1);
        out[out_len - 1] = '\0';
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return 0;
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
    char mapped_path[256];
    mapped_path[0] = '\0';

    if (!handle && find_gtcore_mapped_path(mapped_path, sizeof(mapped_path))) {
        handle = dlopen(mapped_path, RTLD_NOW | RTLD_NOLOAD);
        if (!handle) {
            // Fallback: try normal dlopen on mapped path.
            handle = dlopen(mapped_path, RTLD_NOW);
        }
    }
    if (!handle) {
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
        if (!ends_with(module_name, "/libgtcore.so") && strcmp(module_name, "libgtcore.so") != 0) {
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

    dlclose(handle);
}
