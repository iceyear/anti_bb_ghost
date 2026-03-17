#include "register_natives_hook.h"

#include <android/log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)

typedef jint (*RegisterNativesFn)(JNIEnv *, jclass, const JNINativeMethod *, jint);

static RegisterNativesFn old_register_natives = NULL;
static volatile int register_hook_installed = 0;
static volatile int log_register_natives_enabled = 0;
static struct JNINativeInterface *thread_local_jni_table = NULL;

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

static int get_class_name(JNIEnv *env, jclass clazz, char *out, size_t out_len) {
    if (!out || out_len == 0) return 0;
    out[0] = '\0';

    jclass class_cls = (*env)->GetObjectClass(env, clazz);
    if (!class_cls) {
        (*env)->ExceptionClear(env);
        return 0;
    }

    jmethodID get_name = (*env)->GetMethodID(env, class_cls, "getName", "()Ljava/lang/String;");
    if (!get_name) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, class_cls);
        return 0;
    }

    jstring name = (jstring)(*env)->CallObjectMethod(env, clazz, get_name);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, class_cls);
        return 0;
    }

    if (!name) {
        (*env)->DeleteLocalRef(env, class_cls);
        return 0;
    }

    const char *utf = (*env)->GetStringUTFChars(env, name, NULL);
    if (utf) {
        strncpy(out, utf, out_len - 1);
        out[out_len - 1] = '\0';
        (*env)->ReleaseStringUTFChars(env, name, utf);
    }

    (*env)->DeleteLocalRef(env, name);
    (*env)->DeleteLocalRef(env, class_cls);
    return out[0] != '\0';
}

static int ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return 0;
    size_t slen = strlen(s);
    size_t tlen = strlen(suffix);
    if (slen < tlen) return 0;
    return strcmp(s + slen - tlen, suffix) == 0;
}

static jint hooked_register_natives(JNIEnv *env, jclass clazz,
                                    const JNINativeMethod *methods, jint n_methods) {
    if (log_register_natives_enabled && methods && n_methods > 0) {
        int has_target_method = 0;
        for (jint i = 0; i < n_methods; i++) {
            const char *mname = methods[i].name ? methods[i].name : "<null>";
            if (strcmp(mname, "getData") == 0) {
                has_target_method = 1;
                break;
            }
        }

        if (!has_target_method) {
            goto done;
        }

        char class_name[256];
        if (!get_class_name(env, clazz, class_name, sizeof(class_name))) {
            strncpy(class_name, "<unknown>", sizeof(class_name) - 1);
            class_name[sizeof(class_name) - 1] = '\0';
        }

        for (jint i = 0; i < n_methods; i++) {
            const char *mname = methods[i].name ? methods[i].name : "<null>";
            const char *msig = methods[i].signature ? methods[i].signature : "<null>";

            if (strcmp(mname, "getData") != 0) continue;
            if (strcmp(class_name, "com.geetest.core.Core") != 0 &&
                strcmp(class_name, "com.geetest.core.C3326Core") != 0) {
                continue;
            }

            uintptr_t fn = (uintptr_t)methods[i].fnPtr;
            char module_name[256];
            uintptr_t base = find_module_for_addr(fn, module_name, sizeof(module_name));
            uintptr_t off = base ? (fn - base) : 0;

            if (!ends_with(module_name, "/libgtcore.so") && strcmp(module_name, "libgtcore.so") != 0) {
                continue;
            }

            LOGI("RegisterNatives class:%s name:%s sig:%s module:%s module_base:0x%lx offset:0x%lx fn:0x%lx",
                 class_name, mname, msig,
                 module_name[0] ? module_name : "<unknown>",
                 (unsigned long)base,
                 (unsigned long)off,
                 (unsigned long)fn);
        }
    }

done:
    if (old_register_natives) {
        return old_register_natives(env, clazz, methods, n_methods);
    }
    return JNI_ERR;
}

void register_natives_hook_install(JNIEnv *env) {
    if (register_hook_installed) return;
    if (!env || !(*env)) return;

    const struct JNINativeInterface *table = *env;
    if (!table || !table->RegisterNatives) {
        LOGW("RegisterNatives hook install failed: table/register is null");
        return;
    }

    old_register_natives = table->RegisterNatives;

    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t slot = (uintptr_t)&(((struct JNINativeInterface *)table)->RegisterNatives);
    uintptr_t page = slot & ~((uintptr_t)page_size - 1);

    if (mprotect((void *)page, (size_t)page_size, PROT_READ | PROT_WRITE) == 0) {
        ((struct JNINativeInterface *)table)->RegisterNatives = hooked_register_natives;
        mprotect((void *)page, (size_t)page_size, PROT_READ);
        register_hook_installed = 1;
        LOGI("RegisterNatives hook installed (global table patch)");
        return;
    }

    thread_local_jni_table = (struct JNINativeInterface *)malloc(sizeof(struct JNINativeInterface));
    if (!thread_local_jni_table) {
        LOGW("RegisterNatives hook install failed: malloc fallback table failed");
        return;
    }
    memcpy(thread_local_jni_table, table, sizeof(struct JNINativeInterface));
    thread_local_jni_table->RegisterNatives = hooked_register_natives;
    *env = (const struct JNINativeInterface *)thread_local_jni_table;
    register_hook_installed = 1;
    LOGI("RegisterNatives hook installed (thread-local table copy)");
}

void register_natives_hook_set_enabled(int enabled) {
    log_register_natives_enabled = enabled ? 1 : 0;
    LOGI("RegisterNatives log switch: %s", log_register_natives_enabled ? "ON" : "OFF");
}
