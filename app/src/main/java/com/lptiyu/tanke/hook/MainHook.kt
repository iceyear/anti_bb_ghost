package com.lptiyu.tanke.hook

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        private var isBypassed = false

        private val suspiciousKeywords = arrayOf(
            "org.lsposed",
            "de.robv.android.xposed",
            "LSPHooker",
            "com.elder.xposed",
            "HookBridge",
            "SandHook",
            "EdXposed",
            "me.weishu.epic",
            "top.canyie.pine",
            "com.swift.sandhook",
            "J.callback"
        )

        /**
         * 彻底洗白异常堆栈。
         * 如果一个栈帧包含了可疑关键字，或者是被可疑框架通过反射调用的 Method.invoke，则一并剔除。
         */
        private fun scrubStackTrace(throwable: Throwable?) {
            var cause = throwable
            while (cause != null) {
                val originalTrace = cause.stackTrace
                if (originalTrace != null) {
                    val cleanTrace = mutableListOf<StackTraceElement>()
                    var skipNextReflection = false

                    for (i in originalTrace.indices) {
                        val element = originalTrace[i]
                        val className = element.className
                        val methodName = element.methodName

                        val isSuspicious = suspiciousKeywords.any { keyword ->
                            className.contains(keyword) || methodName.contains(keyword)
                        }

                        if (isSuspicious) {
                            skipNextReflection = true
                            continue
                        }

                        if (skipNextReflection && className == "java.lang.reflect.Method" && methodName == "invoke") {
                            skipNextReflection = false
                            continue
                        }

                        skipNextReflection = false
                        cleanTrace.add(element)
                    }

                    if (cleanTrace.size != originalTrace.size) {
                        cause.stackTrace = cleanTrace.toTypedArray()
                        XposedBridge.log("TankeHook: Scrubbed ${originalTrace.size - cleanTrace.size} suspicious frames from ${cause.javaClass.simpleName}.")
                    }
                }
                cause = cause.cause
            }
        }

        private fun bypassGhostInstanceDetection() {
            if (isBypassed) return
            isBypassed = true
            XposedBridge.log("TankeHook: Initializing Ghost Instance stack trace scrubber...")

            // 1. Hook LoadedApk.createOrUpdateClassLoaderLocked
            try {
                val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
                val createClassLoaderMethod = XposedHelpers.findMethodExact(
                    loadedApkClass,
                    "createOrUpdateClassLoaderLocked",
                    List::class.java
                )

                XposedBridge.hookMethod(createClassLoaderMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        // 如果抛出了异常（比如 NullPointerException 由于幽灵对象导致）
                        // 在壳捕获到之前，洗白它！
                        if (param.hasThrowable()) {
                            scrubStackTrace(param.throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked LoadedApk.createOrUpdateClassLoaderLocked for stack scrubbing")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook LoadedApk: ${e.message}")
            }

            // 2. Hook ActivityThread.attach
            try {
                val activityThreadClass = XposedHelpers.findClass("android.app.ActivityThread", null)
                val attachMethod = XposedHelpers.findMethodExact(
                    activityThreadClass,
                    "attach",
                    Boolean::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType
                )

                XposedBridge.hookMethod(attachMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.hasThrowable()) {
                            scrubStackTrace(param.throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked ActivityThread.attach for stack scrubbing")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook ActivityThread: ${e.message}")
            }

            // 3. Hook ClassLoader.loadClass to catch ClassNotFoundException immediately
            // 这是为了捕获 appComponentFactory 被篡改时抛出的 ClassNotFoundException
            try {
                val classLoaderClass = ClassLoader::class.java
                val loadClassMethod = classLoaderClass.getDeclaredMethod("loadClass", String::class.java)
                XposedBridge.hookMethod(loadClassMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.hasThrowable()) {
                            scrubStackTrace(param.throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked ClassLoader.loadClass for stack scrubbing")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook ClassLoader.loadClass: ${e.message}")
            }

            // 4. Hook Throwable.getStackTrace (兜底防护)
            try {
                val getStackTraceMethod = Throwable::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(getStackTraceMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val elements = param.result as? Array<StackTraceElement> ?: return
                        val cleanTrace = mutableListOf<StackTraceElement>()
                        var skipNextReflection = false

                        for (i in elements.indices) {
                            val element = elements[i]
                            val className = element.className
                            val methodName = element.methodName

                            val isSuspicious = suspiciousKeywords.any { keyword ->
                                className.contains(keyword) || methodName.contains(keyword)
                            }

                            if (isSuspicious) {
                                skipNextReflection = true
                                continue
                            }

                            if (skipNextReflection && className == "java.lang.reflect.Method" && methodName == "invoke") {
                                skipNextReflection = false
                                continue
                            }

                            skipNextReflection = false
                            cleanTrace.add(element)
                        }

                        if (cleanTrace.size != elements.size) {
                            param.result = cleanTrace.toTypedArray()
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Throwable.getStackTrace successfully")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Throwable.getStackTrace: ${e.message}")
            }
        }
    }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        bypassGhostInstanceDetection()
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") {
            return
        }
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")
    }
}
