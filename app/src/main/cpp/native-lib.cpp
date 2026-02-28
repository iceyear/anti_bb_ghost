#include <jni.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cstdint>
#include <cstring>
#include "shadowhook.h"

#define LOG_TAG "TankeHook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

bool is_readable(void* addr, size_t len) {
    if (!addr) return false;
    int fd[2];
    if (pipe(fd) < 0) return false;

    // Attempt to write the memory to the pipe. If it fails with EFAULT, it's not mapped/readable.
    ssize_t ret = write(fd[1], addr, len);
    close(fd[0]);
    close(fd[1]);
    return ret == (ssize_t)len;
}

void nop_64(void* addr) {
    if (!addr) return;
    size_t page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((uintptr_t)addr & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        // AArch64 NOP instruction: 0xD503201F
        uint32_t nop_instr = 0xD503201F;
        memcpy(addr, &nop_instr, sizeof(nop_instr));
        // Clear instruction cache
        __builtin___clear_cache((char*)addr, (char*)addr + sizeof(nop_instr));
        LOGD("Successfully patched NOP at %p", addr);
    } else {
        LOGE("Failed to mprotect at %p", page_start);
    }
}

typedef int (*clone_func_t)(void* fn, void* child_stack, int flags, void* arg, void* ptid, void* newtls, void* ctid);
static clone_func_t orig_clone = nullptr;

static int my_clone(void* fn, void* child_stack, int flags, void* arg, void* ptid, void* newtls, void* ctid) {
    if (arg != nullptr) {
        // Equivalent to `args[3].add(96).readPointer()` in Frida
        void* target_ptr = (void*)((uintptr_t)arg + 96);

        // Safety check before reading the pointer
        if (is_readable(target_ptr, sizeof(void*))) {
            void* addr = *(void**)target_ptr;
            if (addr != nullptr && is_readable(addr, 4)) {
                // Determine module info
                Dl_info info;
                if (dladdr(addr, &info) != 0 && info.dli_fname != nullptr) {
                    const char* so_name = info.dli_fname;
                    void* so_base = info.dli_fbase;
                    uintptr_t offset = (uintptr_t)addr - (uintptr_t)so_base;

                    if (strstr(so_name, "libDexHelper.so") != nullptr) {
                        LOGD("===============> %s %p %zx %zx", so_name, addr, offset, offset);
                        nop_64(addr);
                    }
                }
            }
        }
    }

    // Call original clone with all 7 potential arguments
    return orig_clone(fn, child_stack, flags, arg, ptid, newtls, ctid);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("TankeHook native library loaded");

    // Initialize ShadowHook (SHADOWHOOK_MODE_SHARED = 0)
    shadowhook_init(SHADOWHOOK_MODE_SHARED, true);

    void* stub = shadowhook_hook_sym_name(
        "libc.so",
        "clone",
        (void*)my_clone,
        (void**)&orig_clone
    );

    if (stub != nullptr) {
        LOGD("Hook installed successfully.");
    } else {
        LOGE("Failed to install hook: %d", shadowhook_get_errno());
    }

    return JNI_VERSION_1_6;
}
