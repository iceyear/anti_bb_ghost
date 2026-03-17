#include "artmethod_probe.h"

#include <android/log.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

typedef struct {
    uintptr_t start;
    uintptr_t end;
    int executable;
    char path[256];
} map_range_t;

static int collect_gtcore_ranges(map_range_t *out, int max_count, uintptr_t *module_base) {
    if (!out || max_count <= 0) return 0;
    if (module_base) *module_base = 0;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "libgtcore.so") == NULL) continue;

        unsigned long start = 0, end = 0, file_off = 0, inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255[^\n]",
                       &start, &end, perms, &file_off, dev, &inode, path);
        if (n < 6) continue;

        if (count < max_count) {
            out[count].start = (uintptr_t)start;
            out[count].end = (uintptr_t)end;
            out[count].executable = (strchr(perms, 'x') != NULL) ? 1 : 0;
            if (n >= 7) {
                const char *p = path;
                while (*p == ' ') p++;
                strncpy(out[count].path, p, sizeof(out[count].path) - 1);
                out[count].path[sizeof(out[count].path) - 1] = '\0';
            } else {
                out[count].path[0] = '\0';
            }
            count++;
        }

        if (module_base && (*module_base == 0 || (uintptr_t)start < *module_base)) {
            *module_base = (uintptr_t)start;
        }
    }

    fclose(fp);
    return count;
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
