package com.lptiyu.tanke.hook

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * 极验 getData 调试模块。
 *
 * 目标：在 com.geetest.core.Core.getData(...) 被真实调用时，
 * 通过 FromReflectedMethod + native ArtMethod 槽位扫描打印 libgtcore.so 内的候选 entrypoint 偏移。
 */
object GeetestHooks {

    private var installed = false
    private var dumpedContextOnly = false
    private var dumpedWithConfig = false
    private var callsiteFallbackInstalled = false
    private var callsiteHookCount = 0
    private val callsiteHookedClasses = HashSet<String>()

    fun install(classLoader: ClassLoader) {
        if (!HookPrefs.logRegisterNatives || installed) return

        try {
            val coreClass = XposedHelpers.findClass("com.geetest.core.Core", classLoader)
            hookCoreGetData(coreClass)
            installed = true
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: Geetest hooks deferred: ${e.message}")
        }

        if (!callsiteFallbackInstalled) {
            callsiteFallbackInstalled = true
            XposedBridge.log("TankeHook: Geetest callsite fallback armed")
        }
    }

    fun onClassLoaded(name: String, clazz: Class<*>) {
        if (!HookPrefs.logRegisterNatives) return
        if (!installed && name == "com.geetest.core.Core") {
            XposedBridge.log("TankeHook: Geetest Core observed via ClassLoader monitor")
            hookCoreGetData(clazz)
            installed = true
            return
        }

        // Fallback: hook geetest callsites directly; when hit, dump Core.getData ArtMethod entry.
        if (name.startsWith("com.geetest.core.") && name != "com.geetest.core.Core") {
            installCallsiteFallback(name, clazz)
        }
    }

    private fun hookCoreGetData(coreClass: Class<*>) {
        var count = 0
        for (method in coreClass.declaredMethods) {
            if (method.name != "getData") continue
            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    val reflected = method
                    when (reflected.parameterTypes.size) {
                        1 -> if (!dumpedContextOnly) {
                            dumpedContextOnly = true
                            NativeHelper.dumpArtMethodEntry(reflected, "Core.getData(Context)")
                        }
                        2 -> if (!dumpedWithConfig) {
                            dumpedWithConfig = true
                            NativeHelper.dumpArtMethodEntry(reflected, "Core.getData(Context,GeeGuardConfiguration)")
                        }
                    }
                }
            })
            count++
        }
        XposedBridge.log("TankeHook: Hooked Geetest Core.getData ($count overloads)")
    }

    private fun installCallsiteFallback(name: String, clazz: Class<*>) {
        synchronized(callsiteHookedClasses) {
            if (!callsiteHookedClasses.add(name)) return
        }

        for (method in clazz.declaredMethods) {
            val p = method.parameterTypes
            if (p.size > 4) continue
            if (method.returnType != String::class.java && method.returnType != Void.TYPE) continue

            try {
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (dumpedContextOnly && dumpedWithConfig) return
                        tryDumpFromCoreClass(clazz.classLoader)
                    }
                })
                callsiteHookCount++
            } catch (_: Throwable) {}
        }

        if (callsiteHookCount > 0 && callsiteHookCount % 20 == 0) {
            XposedBridge.log("TankeHook: Geetest callsite fallback hooks=$callsiteHookCount")
        }
    }

    private fun tryDumpFromCoreClass(loader: ClassLoader?) {
        try {
            val core = XposedHelpers.findClass("com.geetest.core.Core", loader)
            for (m in core.declaredMethods) {
                if (m.name != "getData") continue
                when (m.parameterTypes.size) {
                    1 -> if (!dumpedContextOnly) {
                        dumpedContextOnly = true
                        NativeHelper.dumpArtMethodEntry(m, "Core.getData(Context)-fallback")
                    }
                    2 -> if (!dumpedWithConfig) {
                        dumpedWithConfig = true
                        NativeHelper.dumpArtMethodEntry(m, "Core.getData(Context,GeeGuardConfiguration)-fallback")
                    }
                }
            }
        } catch (_: Throwable) {}
    }
}
