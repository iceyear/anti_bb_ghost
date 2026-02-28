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
#include <sys/syscall.h>
#include <android/log.h>

#if defined(__aarch64__)
#include <ucontext.h>
#endif

#define TAG "TankeHook-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

static struct sigaction old_sa;
static volatile int handler_installed = 0;

static void chain_old_handler(int sig, siginfo_t *info, void *ucontext) {
    if (old_sa.sa_flags & SA_SIGINFO) {
        if (old_sa.sa_sigaction) {
            old_sa.sa_sigaction(sig, info, ucontext);
            return;
        }
    }
    if (old_sa.sa_handler != SIG_DFL && old_sa.sa_handler != SIG_IGN) {
        old_sa.sa_handler(sig);
        return;
    }
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    uintptr_t fault_addr = (uintptr_t)info->si_addr;

    /* Only intercept null-page crashes (< 4KB) */
    if (fault_addr >= 0x1000) {
        chain_old_handler(sig, info, ucontext);
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
    chain_old_handler(sig, info, ucontext);
#endif
}

JNIEXPORT void JNICALL
Java_com_lptiyu_tanke_hook_NativeHelper_nativeInstallHandler(JNIEnv *env, jclass clazz) {
    if (handler_installed) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;  /* Use alternate signal stack */
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, &old_sa) == 0) {
        handler_installed = 1;
        LOGI("SIGSEGV handler installed successfully");
    } else {
        LOGW("Failed to install SIGSEGV handler");
    }
}
