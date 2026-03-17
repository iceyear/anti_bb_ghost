/*
 * SIGSEGV signal handler for anti-hook detection bypass.
 *
 * The packer detects Xposed, then deliberately crashes with corrupted registers:
 *   PC=0x88c, LR=0, SP=0 — making normal recovery impossible.
 *
 * Strategy:
 *   For recoverable crashes (valid LR/SP): simulate function return.
 *   For unrecoverable crashes (LR=0, SP=0): terminate ONLY the detection thread
 *   using syscall(SYS_exit, 0), which exits just the calling thread without
 *   killing the whole process. The main app thread survives.
 */

#include <jni.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <android/log.h>

#include "register_natives_hook.h"
#include "artmethod_probe.h"
#include "static_jni_probe.h"
#include "dexhelper_bypass.h"

#if defined(__aarch64__)
#include <ucontext.h>
#endif

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

static struct sigaction old_segv_sa;
static struct sigaction old_ill_sa;
static volatile int handler_installed = 0;
static volatile int frida_bypass_enabled = 0;
static volatile int sigill_guard_started = 0;

static void sigill_handler(int sig, siginfo_t *info, void *ucontext);

static void install_sigill_handler(int preserve_old) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigill_handler;
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    if (preserve_old) {
        if (sigaction(SIGILL, &sa, &old_ill_sa) == 0) {
            LOGI("SIGILL handler installed successfully");
        } else {
            LOGW("Failed to install SIGILL handler");
        }
        return;
    }

    struct sigaction current;
    memset(&current, 0, sizeof(current));
    if (sigaction(SIGILL, NULL, &current) == 0) {
        if ((current.sa_flags & SA_SIGINFO) && current.sa_sigaction == sigill_handler) {
            return;
        }
    }

    if (sigaction(SIGILL, &sa, NULL) == 0) {
        LOGW("SIGILL handler was replaced, restored ours");
    }
}

static void *sigill_guard_thread(void *arg) {
    (void)arg;
    /* Keep SIGILL handler sticky for ~30s after startup. */
    for (int i = 0; i < 600; i++) {
        if (!frida_bypass_enabled) break;
        install_sigill_handler(0);
        usleep(50000);
    }
    sigill_guard_started = 0;
    return NULL;
}

static void chain_old_handler(int sig, siginfo_t *info, void *ucontext, struct sigaction *old_sa) {
    if (old_sa->sa_flags & SA_SIGINFO) {
        if (old_sa->sa_sigaction) {
            old_sa->sa_sigaction(sig, info, ucontext);
            return;
        }
    }
    if (old_sa->sa_handler != SIG_DFL && old_sa->sa_handler != SIG_IGN) {
        old_sa->sa_handler(sig);
        return;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    uintptr_t fault_addr = (uintptr_t)info->si_addr;

    /* Only intercept null-page crashes (< 4KB) */
    if (fault_addr >= 0x1000) {
        chain_old_handler(sig, info, ucontext, &old_segv_sa);
        return;
    }

#if defined(__aarch64__)
    ucontext_t *ctx = (ucontext_t *)ucontext;
    uint64_t lr  = ctx->uc_mcontext.regs[30];
    uint64_t sp  = ctx->uc_mcontext.sp;
    uint64_t pc  = ctx->uc_mcontext.pc;

    /*
     * Case 1: Recoverable — LR and SP are valid.
     * Simulate function return: PC = LR, X0 = 0 (return null).
     */
    if (lr > 0x1000 && sp > 0x1000) {
        ctx->uc_mcontext.pc = lr;
        ctx->uc_mcontext.regs[0] = 0;
        LOGI("Recovered SIGSEGV at 0x%lx (PC=0x%lx → LR=0x%lx)",
             (unsigned long)fault_addr, (unsigned long)pc, (unsigned long)lr);
        return;
    }

    /*
     * Case 2: Unrecoverable — LR and/or SP are zeroed (deliberate kill).
     * The packer detected hooks and corrupted all registers before crashing.
     * We can't return anywhere, but we CAN kill just this thread.
     *
     * syscall(__NR_exit, 0) terminates ONLY the calling thread (not the process).
     * The signal handler runs on an alternate signal stack (set up by bionic),
     * so we have a valid stack even though user SP is 0.
     */
    LOGI("Deliberate crash detected at 0x%lx (PC=0x%lx LR=0x%lx SP=0x%lx) — killing thread only",
         (unsigned long)fault_addr, (unsigned long)pc, (unsigned long)lr, (unsigned long)sp);
    syscall(__NR_exit, 0);
    /* NOT REACHED */
#else
    chain_old_handler(sig, info, ucontext, &old_segv_sa);
#endif
}

static int is_likely_frida_thread(void) {
    char name[17] = {0};
    if (prctl(PR_GET_NAME, (unsigned long)name, 0, 0, 0) != 0) return 0;
    if (strstr(name, "frida") != NULL) return 1;
    if (strstr(name, "gum-js") != NULL) return 1;
    if (strstr(name, "gmain") != NULL) return 1;
    if (strstr(name, "lhost") != NULL) return 1;
    return 0;
}

static int is_main_thread(void) {
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(__NR_gettid);
    return pid == tid;
}

static void sigill_handler(int sig, siginfo_t *info, void *ucontext) {
#if defined(__aarch64__)
    if (!frida_bypass_enabled) {
        chain_old_handler(sig, info, ucontext, &old_ill_sa);
        return;
    }

    ucontext_t *ctx = (ucontext_t *)ucontext;
    uint64_t lr = ctx->uc_mcontext.regs[30];
    uint64_t sp = ctx->uc_mcontext.sp;
    uint64_t pc = ctx->uc_mcontext.pc;

    if (!is_main_thread() && (is_likely_frida_thread() || lr == 0 || sp == 0 || info->si_code == ILL_ILLOPC)) {
        LOGI("SIGILL blocked (code=%d PC=0x%lx LR=0x%lx SP=0x%lx) — exiting non-main thread",
             info->si_code, (unsigned long)pc, (unsigned long)lr, (unsigned long)sp);
        syscall(__NR_exit, 0);
    }
#endif
    chain_old_handler(sig, info, ucontext, &old_ill_sa);
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeInstallHandler(JNIEnv *env, jclass clazz) {
    if (handler_installed) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;  /* Use alternate signal stack */
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &old_segv_sa) == 0) {
        LOGI("SIGSEGV handler installed successfully");
    } else {
        LOGW("Failed to install SIGSEGV handler");
    }

    install_sigill_handler(1);

    handler_installed = 1;
    register_natives_hook_install(env);
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeSetRegisterNativesLogEnabled(
        JNIEnv *env, jclass clazz, jboolean enabled) {
    (void)env;
    (void)clazz;
    register_natives_hook_set_enabled(enabled ? 1 : 0);
    static_jni_probe_set_enabled(enabled ? 1 : 0);
    static_jni_probe_try_log();
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeSetFridaBypassEnabled(
        JNIEnv *env, jclass clazz, jboolean enabled) {
    (void)env;
    (void)clazz;
    frida_bypass_enabled = enabled ? 1 : 0;
    LOGI("Frida bypass switch: %s", frida_bypass_enabled ? "ON" : "OFF");
    dexhelper_bypass_set_enabled(enabled ? 1 : 0);

    if (frida_bypass_enabled && !sigill_guard_started) {
        pthread_t t;
        if (pthread_create(&t, NULL, sigill_guard_thread, NULL) == 0) {
            pthread_detach(t);
            sigill_guard_started = 1;
            LOGI("SIGILL guard thread started");
        }
    }
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeTryPatchDexHelperNow(
        JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    dexhelper_bypass_try_patch_now();
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeProbeStaticJniGetDataSymbols(
        JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    static_jni_probe_try_log();
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeDumpArtMethodEntry(
        JNIEnv *env, jclass clazz, jobject reflectedMethod, jstring label) {
    (void)clazz;
    artmethod_probe_dump(env, reflectedMethod, label);
}
