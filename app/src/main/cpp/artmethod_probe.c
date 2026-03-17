#define _GNU_SOURCE 1

#include "artmethod_probe.h"

#include <android/log.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <string.h>

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct {
    uintptr_t start;
    uintptr_t end;
    int executable;
    char path[256];
} map_range_t;

typedef struct {
    map_range_t *ranges;
    int max_count;
    int count;
    uintptr_t module_base;
    char module_path[256];
} gtcore_module_scan_t;

static int module_name_contains_gtcore(const char *name) {
    return name && strstr(name, "libgtcore.so") != NULL;
}

static int phdr_collect_gtcore_cb(struct dl_phdr_info *info, size_t info_size, void *data) {
    (void)info_size;
    gtcore_module_scan_t *scan = (gtcore_module_scan_t *)data;
    const char *name = (info && info->dlpi_name) ? info->dlpi_name : NULL;
    if (!scan || !module_name_contains_gtcore(name)) return 0;

    scan->module_base = (uintptr_t)info->dlpi_addr;
    if (name && *name) {
        strncpy(scan->module_path, name, sizeof(scan->module_path) - 1);
        scan->module_path[sizeof(scan->module_path) - 1] = '\0';
    } else {
        strncpy(scan->module_path, "<phdr>", sizeof(scan->module_path) - 1);
        scan->module_path[sizeof(scan->module_path) - 1] = '\0';
    }

    for (ElfW(Half) i = 0; i < info->dlpi_phnum && scan->count < scan->max_count; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;

        uintptr_t start = (uintptr_t)info->dlpi_addr + (uintptr_t)ph->p_vaddr;
        uintptr_t end = start + (uintptr_t)ph->p_memsz;
        if (end <= start) continue;

        scan->ranges[scan->count].start = start;
        scan->ranges[scan->count].end = end;
        scan->ranges[scan->count].executable = (ph->p_flags & PF_X) ? 1 : 0;
        strncpy(scan->ranges[scan->count].path,
                scan->module_path,
                sizeof(scan->ranges[scan->count].path) - 1);
        scan->ranges[scan->count].path[sizeof(scan->ranges[scan->count].path) - 1] = '\0';
        scan->count++;
    }

    return 1;
}

static int collect_gtcore_ranges(map_range_t *out, int max_count, uintptr_t *module_base) {
    if (!out || max_count <= 0) return 0;
    if (module_base) *module_base = 0;

    gtcore_module_scan_t scan;
    memset(&scan, 0, sizeof(scan));
    scan.ranges = out;
    scan.max_count = max_count;

    dl_iterate_phdr(phdr_collect_gtcore_cb, &scan);
    if (module_base) *module_base = scan.module_base;
    return scan.count;
}

void artmethod_probe_dump(JNIEnv *env, jobject reflected_method, jstring label) {
    if (!env || !reflected_method) return;

    const char *label_utf = NULL;
    if (label) {
        label_utf = (*env)->GetStringUTFChars(env, label, NULL);
    }

    jmethodID mid = (*env)->FromReflectedMethod(env, reflected_method);
    if (!mid) {
        if (label_utf) (*env)->ReleaseStringUTFChars(env, label, label_utf);
        return;
    }

    map_range_t ranges[64];
    uintptr_t module_base = 0;
    int range_count = collect_gtcore_ranges(ranges, 64, &module_base);
    if (range_count <= 0 || module_base == 0) {
        if (label_utf) {
            LOGI("ArtMethodProbe %s: libgtcore.so not mapped yet", label_utf);
            (*env)->ReleaseStringUTFChars(env, label, label_utf);
        }
        return;
    }

    uintptr_t art = (uintptr_t)mid;
    uintptr_t *slots = (uintptr_t *)art;

    int hit = 0;
    for (int i = 0; i < 48; i++) {
        uintptr_t candidate = slots[i];
        if (candidate < 0x10000) continue;

        for (int r = 0; r < range_count; r++) {
            if (!ranges[r].executable) continue;
            if (candidate < ranges[r].start || candidate >= ranges[r].end) continue;

            uintptr_t offset = candidate - module_base;
            LOGI("ArtMethodProbe %s artMethod:0x%lx slot:%d ptr:0x%lx module:%s module_base:0x%lx offset:0x%lx",
                 label_utf ? label_utf : "<null>",
                 (unsigned long)art,
                 i,
                 (unsigned long)candidate,
                 ranges[r].path[0] ? ranges[r].path : "<unknown>",
                 (unsigned long)module_base,
                 (unsigned long)offset);
            hit = 1;
            break;
        }
    }

    if (!hit) {
        LOGI("ArtMethodProbe %s artMethod:0x%lx no executable pointer hit in libgtcore slots[0..47]",
             label_utf ? label_utf : "<null>", (unsigned long)art);
    }

    if (label_utf) {
        (*env)->ReleaseStringUTFChars(env, label, label_utf);
    }
}
