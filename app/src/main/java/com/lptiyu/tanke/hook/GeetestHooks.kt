package com.lptiyu.tanke.hook

import android.content.Context
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * 极验 getData 定位与观测模块。
 *
 * 这版不再只依赖 Core.getData 在安装期就可见，而是同时覆盖：
 *  - com.geetest.core.GeeGuard 的公开入口
 *  - com.geetest.core.C7072c 的内部聚合逻辑
 *  - 业务侧 GeeGuard.CallbackHandler 回调
 *
 * 这样即使 SecNeo 延迟解出 geetest 相关类，也能在真实调用发生时：
 *  1. 打印 getData 配置与返回 token
 *  2. 触发 native 侧 RegisterNatives / ArtMethod / StaticJNI 探针
 */
object GeetestHooks {

    private const val CORE_CLASS = "com.geetest.core.Core"
    private const val GEE_GUARD_CLASS = "com.geetest.core.GeeGuard"
    private const val INTERNAL_CLASS = "com.geetest.core.C7072c"
    private const val INTERNAL_CLASS_ORIG = "com.geetest.core.c"
    private const val WRAPPER_CLASS = "com.geetest.core.C7088e"
    private const val WRAPPER_CLASS_ORIG = "com.geetest.core.e"

    private var installLogged = false
    private var coreHooked = false
    private var geeGuardHooked = false
    private var internalHooked = false
    private var pollerStarted = false
    private var dumpedContextOnly = false
    private var dumpedWithConfig = false
    private var postDumpedContextOnly = false
    private var postDumpedWithConfig = false
    private val hookedCallbackClasses = HashSet<String>()
    private val hookedDynamicGeetestClasses = HashSet<String>()

    fun install(classLoader: ClassLoader) {
        if (!HookPrefs.logRegisterNatives) return

        if (!installLogged) {
            installLogged = true
            XposedBridge.log("TankeHook: Geetest observers armed")
        }

        tryHookKnownClasses(classLoader, "initial")
        ensurePolling(classLoader)
    }

    fun onClassLoaded(name: String, clazz: Class<*>) {
        if (!HookPrefs.logRegisterNatives) return

        when (name) {
            CORE_CLASS -> hookCoreGetData(clazz, "monitor")
            GEE_GUARD_CLASS -> hookGeeGuard(clazz, "monitor")
            INTERNAL_CLASS -> hookInternalFlow(clazz, "monitor")
        }

        if (name.startsWith("com.geetest.core.")) {
            NativeHelper.probeStaticJniGetDataSymbols()
            hookDynamicGeetestClass(name, clazz, "monitor")
        }

        if (name.startsWith("com.lptiyu.tanke.activities.school_run.RunHelper") ||
            name.startsWith("com.lptiyu.tanke.fragments.TrackFragment")
        ) {
            maybeHookCallbackHandler(name, clazz)
        }
    }

    private fun tryHookKnownClasses(loader: ClassLoader, reason: String) {
        tryHookClass(loader, CORE_CLASS, reason) { hookCoreGetData(it, reason) }
        tryHookClass(loader, GEE_GUARD_CLASS, reason) { hookGeeGuard(it, reason) }
        tryHookClass(loader, INTERNAL_CLASS, reason) { hookInternalFlow(it, reason) }
        tryHookClass(loader, INTERNAL_CLASS_ORIG, reason) { hookDynamicGeetestClass(INTERNAL_CLASS_ORIG, it, reason) }
        tryHookClass(loader, WRAPPER_CLASS, reason) { hookDynamicGeetestClass(WRAPPER_CLASS, it, reason) }
        tryHookClass(loader, WRAPPER_CLASS_ORIG, reason) { hookDynamicGeetestClass(WRAPPER_CLASS_ORIG, it, reason) }
    }

    private fun tryHookClass(
        loader: ClassLoader,
        className: String,
        reason: String,
        action: (Class<*>) -> Unit
    ) {
        try {
            action(findClassIfPresent(loader, className))
        } catch (e: Throwable) {
            HookPrefs.vlog("Geetest class not ready via $reason: $className (${e.message})")
        }
    }

    private fun findClassIfPresent(loader: ClassLoader, className: String): Class<*> {
        return Class.forName(className, false, loader)
    }

    private fun ensurePolling(loader: ClassLoader) {
        if (pollerStarted) return
        pollerStarted = true

        Thread {
            repeat(240) { index ->
                try {
                    tryHookKnownClasses(loader, "poll")
                } catch (e: Throwable) {
                    HookPrefs.vlog("Geetest poll failed: ${e.message}")
                }

                if (index == 0) {
                    XposedBridge.log("TankeHook: Geetest class poller started")
                }

                if (coreHooked && geeGuardHooked && internalHooked) {
                    return@Thread
                }

                try {
                    Thread.sleep(500)
                } catch (_: InterruptedException) {
                    return@Thread
                }
            }
        }.apply {
            name = "tanke-geetest-poller"
            isDaemon = true
            start()
        }
    }

    private fun hookCoreGetData(coreClass: Class<*>, reason: String) {
        if (coreHooked) return

        var count = 0
        for (method in coreClass.declaredMethods) {
            if (method.name != "getData") continue
            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    NativeHelper.probeStaticJniGetDataSymbols()
                    dumpCoreMethodOnce(method)
                    XposedBridge.log(
                        "TankeHook: Geetest Core.${method.name}${signatureSuffix(method)} args=${describeArgs(param.args)}"
                    )
                }

                override fun afterHookedMethod(param: MethodHookParam) {
                    dumpCoreMethodAfterLoad(method)
                    NativeHelper.probeStaticJniGetDataSymbols()
                    XposedBridge.log(
                        "TankeHook: Geetest Core.${method.name}${signatureSuffix(method)} result=${describeResult(param.result)}"
                    )
                }
            })
            count++
        }

        coreHooked = count > 0
        if (coreHooked) {
            XposedBridge.log("TankeHook: Hooked Geetest Core.getData ($count overloads) via $reason")
        }
    }

    private fun hookGeeGuard(geeGuardClass: Class<*>, reason: String) {
        if (geeGuardHooked) return

        var count = 0
        for (method in geeGuardClass.declaredMethods) {
            if (!Modifier.isStatic(method.modifiers)) continue
            if (method.name != "getData" &&
                method.name != "fetchReceipt" &&
                method.name != "submitReceipt"
            ) {
                continue
            }

            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    tryDumpCoreFromLoader(geeGuardClass.classLoader, "GeeGuard.${method.name}")
                    XposedBridge.log(
                        "TankeHook: GeeGuard.${method.name}${signatureSuffix(method)} args=${describeArgs(param.args)}"
                    )
                }

                override fun afterHookedMethod(param: MethodHookParam) {
                    val result = when (method.returnType) {
                        Void.TYPE -> "void"
                        else -> describeResult(param.result)
                    }
                    XposedBridge.log(
                        "TankeHook: GeeGuard.${method.name}${signatureSuffix(method)} result=$result"
                    )
                }
            })
            count++
        }

        geeGuardHooked = count > 0
        if (geeGuardHooked) {
            XposedBridge.log("TankeHook: Hooked GeeGuard entrypoints ($count methods) via $reason")
        }
    }

    private fun hookInternalFlow(clazz: Class<*>, reason: String) {
        if (internalHooked) return

        var count = 0
        for (method in clazz.declaredMethods) {
            if (method.name != "m39066a" && method.name != "m39077a") continue

            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    tryDumpCoreFromLoader(clazz.classLoader, "C7072c.${method.name}")
                    XposedBridge.log(
                        "TankeHook: C7072c.${method.name}${signatureSuffix(method)} args=${describeArgs(param.args)}"
                    )
                }

                override fun afterHookedMethod(param: MethodHookParam) {
                    val result = when (method.returnType) {
                        Void.TYPE -> "void"
                        else -> describeResult(param.result)
                    }
                    XposedBridge.log(
                        "TankeHook: C7072c.${method.name}${signatureSuffix(method)} result=$result"
                    )
                }
            })
            count++
        }

        internalHooked = count > 0
        if (internalHooked) {
            XposedBridge.log("TankeHook: Hooked C7072c flow ($count methods) via $reason")
        }
    }

    private fun hookDynamicGeetestClass(name: String, clazz: Class<*>, reason: String) {
        if (name == CORE_CLASS && coreHooked) return
        if (name == GEE_GUARD_CLASS && geeGuardHooked) return
        if (name == INTERNAL_CLASS && internalHooked) return

        synchronized(hookedDynamicGeetestClasses) {
            if (!hookedDynamicGeetestClasses.add(name)) return
        }

        var count = 0
        for (method in clazz.declaredMethods) {
            if (!shouldHookDynamicMethod(method)) continue

            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    tryDumpCoreFromLoader(clazz.classLoader, "$name.${method.name}")
                    XposedBridge.log(
                        "TankeHook: Geetest flow $name.${method.name}${signatureSuffix(method)} args=${describeArgs(param.args)}"
                    )
                }

                override fun afterHookedMethod(param: MethodHookParam) {
                    val result = when (method.returnType) {
                        Void.TYPE -> "void"
                        else -> describeResult(param.result)
                    }
                    XposedBridge.log(
                        "TankeHook: Geetest flow $name.${method.name}${signatureSuffix(method)} result=$result"
                    )
                }
            })
            count++
        }

        if (count > 0) {
            XposedBridge.log("TankeHook: Hooked Geetest dynamic flow $name ($count methods) via $reason")
        }
    }

    private fun maybeHookCallbackHandler(name: String, clazz: Class<*>) {
        synchronized(hookedCallbackClasses) {
            if (!hookedCallbackClasses.add(name)) return
        }

        if (!implementsCallbackHandler(clazz)) return

        var hooked = 0
        for (method in clazz.declaredMethods) {
            if (method.name != "onCompletion") continue
            if (method.parameterTypes.size != 2) continue

            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    XposedBridge.log(
                        "TankeHook: GeeGuard callback ${clazz.name}.onCompletion args=${describeArgs(param.args)}"
                    )
                }
            })
            hooked++
        }

        if (hooked > 0) {
            XposedBridge.log("TankeHook: Hooked GeeGuard callback ${clazz.name} ($hooked methods)")
        }
    }

    private fun tryDumpCoreFromLoader(loader: ClassLoader?, reason: String) {
        if (loader == null) return
        NativeHelper.probeStaticJniGetDataSymbols()

        try {
            val core = XposedHelpers.findClass(CORE_CLASS, loader)
            hookCoreGetData(core, reason)
            for (method in core.declaredMethods) {
                if (method.name != "getData") continue
                dumpCoreMethodOnce(method)
            }
        } catch (e: Throwable) {
            HookPrefs.vlog("Geetest Core not visible via $reason: ${e.message}")
        }
    }

    private fun dumpCoreMethodOnce(method: Method) {
        when (method.parameterTypes.size) {
            1 -> if (!dumpedContextOnly) {
                dumpedContextOnly = true
                NativeHelper.dumpArtMethodEntry(method, "Core.getData(Context)")
            }
            2 -> if (!dumpedWithConfig) {
                dumpedWithConfig = true
                NativeHelper.dumpArtMethodEntry(method, "Core.getData(Context,GeeGuardConfiguration)")
            }
        }
    }

    private fun dumpCoreMethodAfterLoad(method: Method) {
        when (method.parameterTypes.size) {
            1 -> if (!postDumpedContextOnly) {
                postDumpedContextOnly = true
                NativeHelper.dumpArtMethodEntry(method, "Core.getData(Context)-post")
            }
            2 -> if (!postDumpedWithConfig) {
                postDumpedWithConfig = true
                NativeHelper.dumpArtMethodEntry(method, "Core.getData(Context,GeeGuardConfiguration)-post")
            }
        }
    }

    private fun implementsCallbackHandler(clazz: Class<*>): Boolean {
        var current: Class<*>? = clazz
        while (current != null) {
            if (current.interfaces.any { it.name == "com.geetest.core.GeeGuard\$CallbackHandler" }) {
                return true
            }
            current = current.superclass
        }
        return false
    }

    private fun shouldHookDynamicMethod(method: Method): Boolean {
        val params = method.parameterTypes
        if (method.name == "getData" && method.returnType == String::class.java && params.isNotEmpty() &&
            params[0] == Context::class.java
        ) {
            return true
        }

        if ((method.name == "fetchReceipt" || method.name == "submitReceipt") && params.isNotEmpty() &&
            params[0] == Context::class.java
        ) {
            return true
        }

        if (isReceiptType(method.returnType) && params.size >= 3 &&
            params[0] == Context::class.java &&
            params[1] == String::class.java &&
            params[2] == String::class.java
        ) {
            return true
        }

        if (method.returnType == Void.TYPE && params.size >= 4 &&
            params[0] == Context::class.java &&
            params.any { isCallbackHandlerType(it) }
        ) {
            return true
        }

        if (params.isNotEmpty() && params[0] == Context::class.java) {
            if (method.returnType == Void.TYPE && params.any { isCallbackHandlerType(it) }) {
                return true
            }
            if (method.returnType == String::class.java) {
                return true
            }
            if (isReceiptType(method.returnType)) {
                return true
            }
        }

        return false
    }

    private fun isReceiptType(type: Class<*>): Boolean {
        return type.name == "com.geetest.core.GeeGuardReceipt"
    }

    private fun isCallbackHandlerType(type: Class<*>): Boolean {
        return type.name == "com.geetest.core.GeeGuard\$CallbackHandler"
    }

    private fun signatureSuffix(method: Method): String {
        return method.parameterTypes.joinToString(prefix = "(", postfix = ")") { it.simpleName }
    }

    private fun describeArgs(args: Array<out Any?>?): String {
        if (args == null) return "[]"
        return args.joinToString(prefix = "[", postfix = "]") { describeValue(it) }
    }

    private fun describeResult(value: Any?): String {
        return describeValue(value)
    }

    private fun describeValue(value: Any?): String {
        if (value == null) return "null"
        if (value is Context) {
            return "Context(${value.javaClass.name})"
        }

        val className = value.javaClass.name
        return when {
            className == "com.geetest.core.GeeGuardConfiguration" -> describeGeeGuardConfig(value)
            className == "com.geetest.core.GeeGuardReceipt" -> describeGeeGuardReceipt(value)
            value is CharSequence -> formatText(value.toString())
            value is Number || value is Boolean -> value.toString()
            else -> "${className}@${Integer.toHexString(System.identityHashCode(value))}"
        }
    }

    private fun describeGeeGuardConfig(config: Any): String {
        return try {
            val appId = XposedHelpers.callMethod(config, "getAppId") as? String
            val signature = XposedHelpers.callMethod(config, "getContent") as? String
            val level = XposedHelpers.callMethod(config, "getLevel")
            val alInfo = XposedHelpers.callMethod(config, "isAlInfo")
            val devInfo = XposedHelpers.callMethod(config, "isDevInfo")
            "GeeGuardConfiguration(appId=${formatText(appId)}, signature=${formatText(signature)}, level=$level, alInfo=$alInfo, devInfo=$devInfo)"
        } catch (e: Throwable) {
            "GeeGuardConfiguration(error=${e.message})"
        }
    }

    private fun describeGeeGuardReceipt(receipt: Any): String {
        fun field(name: String): String {
            return try {
                formatText(XposedHelpers.getObjectField(receipt, name) as? String)
            } catch (_: Throwable) {
                "<?>"
            }
        }

        return "GeeGuardReceipt(appID=${field("appID")}, geeID=${field("geeID")}, geeToken=${field("geeToken")}, respondedGeeToken=${field("respondedGeeToken")}, geeIDTimestamp=${field("geeIDTimestamp")}, originalResponse=${field("originalResponse")})"
    }

    private fun formatText(value: String?): String {
        if (value == null) return "null"
        val sanitized = value.replace('\n', ' ')
        return if (sanitized.length <= 512) {
            "\"$sanitized\""
        } else {
            "\"${sanitized.take(256)}...${sanitized.takeLast(128)}\"(len=${sanitized.length})"
        }
    }
}
