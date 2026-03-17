#define _GNU_SOURCE 1

#include "register_natives_hook.h"

#include <android/log.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
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

typedef struct {
    uintptr_t addr;
    uintptr_t module_base;
    char module_name[256];
} addr_lookup_t;

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

            uintptr_t fn = (uintptr_t)methods[i].fnPtr;
            char module_name[256];
            uintptr_t base = find_module_for_addr(fn, module_name, sizeof(module_name));
            uintptr_t off = base ? (fn - base) : 0;

            if (!module_name_contains_gtcore(module_name)) {
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
