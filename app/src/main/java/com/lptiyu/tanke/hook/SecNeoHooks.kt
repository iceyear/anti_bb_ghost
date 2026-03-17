package com.lptiyu.tanke.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * SecNeo / Ijiami loader hooks.
 *
 * Current strategy is intentionally non-invasive:
 *  - observe native library loads so we can see which shell library is active
 *  - short-circuit SecNeo's Java-level TracerPid probes
 *  - observe the native `sl(path)` fallback loader when it is used
 */
object SecNeoHooks {

    private var installed = false
    @Volatile private var loggedSecNeoLoad = false
    @Volatile private var loggedSecNeoLoadLib = false
    @Volatile private var loggedTracerPidBypass = false
    @Volatile private var loggedSl = false

    fun install(classLoader: ClassLoader) {
        if (installed) return
        installed = true
        hookSecNeoLoadObserver(classLoader)
        hookSecNeoTracerPidChecks(classLoader)
        hookSecNeoSl(classLoader)
    }

    private fun hookSecNeoLoadObserver(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.secneo.apkwrapper.H",
                classLoader,
                "load",
                android.content.pm.ApplicationInfo::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (!loggedSecNeoLoad) {
                            loggedSecNeoLoad = true
                            XposedBridge.log("TankeHook: SecNeo H.load() entered")
                        }
                    }

                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (HookPrefs.bypassFrida) {
                            NativeHelper.tryPatchDexHelperNow()
                        }
                    }
                }
            )
            XposedBridge.log("TankeHook: Hooked SecNeo H.load() observer")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: SecNeo H.load hook failed: ${e.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                "com.secneo.apkwrapper.H",
                classLoader,
                "loadLib",
                android.content.pm.ApplicationInfo::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (!loggedSecNeoLoadLib) {
                            loggedSecNeoLoadLib = true
                            XposedBridge.log("TankeHook: SecNeo H.loadLib() entered")
                        }
                    }
                }
            )
            XposedBridge.log("TankeHook: Hooked SecNeo H.loadLib() observer")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: SecNeo H.loadLib hook failed: ${e.message}")
        }
    }

    private fun hookSecNeoTracerPidChecks(classLoader: ClassLoader) {
        val bypassHook = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                if (!HookPrefs.bypassFrida) return
                val mode = (param.args.firstOrNull() as? Int) ?: return
                if (mode != 0) return
                if (!loggedTracerPidBypass) {
                    loggedTracerPidBypass = true
                    XposedBridge.log("TankeHook: SecNeo TracerPid probe bypassed")
                }
                param.result = 0
            }
        }

        try {
            XposedHelpers.findAndHookMethod(
                "com.secneo.apkwrapper.H",
                classLoader,
                "Iii1Iii1IIIi1",
                Int::class.javaPrimitiveType,
                bypassHook
            )
            XposedBridge.log("TankeHook: Hooked SecNeo Iii1Iii1IIIi1()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: SecNeo Iii1Iii1IIIi1 hook failed: ${e.message}")
        }

        try {
            XposedHelpers.findAndHookMethod(
                "com.secneo.apkwrapper.H",
                classLoader,
                "Iii1Iii1IlIi1",
                Int::class.javaPrimitiveType,
                bypassHook
            )
            XposedBridge.log("TankeHook: Hooked SecNeo Iii1Iii1IlIi1()")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: SecNeo Iii1Iii1IlIi1 hook failed: ${e.message}")
        }
    }

    private fun hookSecNeoSl(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.secneo.apkwrapper.H",
                classLoader,
                "sl",
                String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val path = param.args[0] as? String ?: return
                        if (!path.contains("DexHelper", ignoreCase = true)) return
                        if (!loggedSl) {
                            loggedSl = true
                            XposedBridge.log("TankeHook: SecNeo sl() observed path=$path")
                        }
                    }
                }
            )
            XposedBridge.log("TankeHook: Hooked SecNeo H.sl() observer")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: SecNeo H.sl hook failed: ${e.message}")
        }
    }
}
