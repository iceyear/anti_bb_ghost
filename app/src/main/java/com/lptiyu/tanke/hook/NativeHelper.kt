package com.lptiyu.tanke.hook

import de.robv.android.xposed.XposedBridge

/**
 * Native helper for installing low-level signal handlers.
 *
 * The SIGSEGV handler catches null-page dereferences caused by ghost objects
 * hitting LSPosed's native bridge. Instead of killing the process, the handler
 * skips the faulting instruction and zeroes the destination register, allowing
 * the bridge to continue (and eventually throw a Java exception that our
 * stack-trace hooks can clean).
 */
object NativeHelper {

    private var loaded = false

    /**
     * Load the native library and install the SIGSEGV handler.
     * Safe to call multiple times — subsequent calls are no-ops.
     *
     * @param modulePath The APK path of our Xposed module (from StartupParam.modulePath).
     *                   Used as fallback for library loading.
     */
    fun install(modulePath: String? = null) {
        if (loaded) return

        try {
            System.loadLibrary("anti_segv")
            loaded = true
        } catch (e: UnsatisfiedLinkError) {
            XposedBridge.log("TankeHook: System.loadLibrary failed: ${e.message}")

            // Fallback: try loading from the module APK's lib directory
            if (modulePath != null) {
                try {
                    val apkDir = java.io.File(modulePath).parent ?: return
                    val soPath = "$apkDir/lib/arm64/libanti_segv.so"
                    Runtime.getRuntime().load(soPath)
                    loaded = true
                } catch (e2: Throwable) {
                    XposedBridge.log("TankeHook: Fallback load also failed: ${e2.message}")
                }
            }
        }

        if (loaded) {
            try {
                nativeInstallHandler()
                XposedBridge.log("TankeHook: Native SIGSEGV handler installed")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to call nativeInstallHandler: ${e.message}")
            }
        }
    }

    fun setRegisterNativesLogEnabled(enabled: Boolean) {
        if (!loaded) return
        try {
            nativeSetRegisterNativesLogEnabled(enabled)
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to set RegisterNatives log switch: ${e.message}")
        }
    }

    fun setFridaBypassEnabled(enabled: Boolean) {
        if (!loaded) return
        try {
            nativeSetFridaBypassEnabled(enabled)
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to set Frida bypass switch: ${e.message}")
        }
    }

    fun tryPatchDexHelperNow() {
        if (!loaded) return
        try {
            nativeTryPatchDexHelperNow()
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to trigger DexHelper patch: ${e.message}")
        }
    }

    fun probeStaticJniGetDataSymbols() {
        if (!loaded) return
        try {
            nativeProbeStaticJniGetDataSymbols()
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to probe static JNI symbols: ${e.message}")
        }
    }

    fun dumpArtMethodEntry(reflectedMethod: java.lang.reflect.Method, label: String) {
        if (!loaded) return
        try {
            nativeDumpArtMethodEntry(reflectedMethod, label)
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Failed to dump ArtMethod entry: ${e.message}")
        }
    }

    @JvmStatic
    private external fun nativeInstallHandler()

    @JvmStatic
    private external fun nativeSetRegisterNativesLogEnabled(enabled: Boolean)

    @JvmStatic
    private external fun nativeSetFridaBypassEnabled(enabled: Boolean)

    @JvmStatic
    private external fun nativeTryPatchDexHelperNow()

    @JvmStatic
    private external fun nativeProbeStaticJniGetDataSymbols()

    @JvmStatic
    private external fun nativeDumpArtMethodEntry(reflectedMethod: java.lang.reflect.Method, label: String)
}
