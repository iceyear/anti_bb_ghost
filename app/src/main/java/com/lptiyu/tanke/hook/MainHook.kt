package com.lptiyu.tanke.hook

import android.util.Log
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
                if (originalTrace != null && originalTrace.isNotEmpty()) {
                    // Quick check to avoid unnecessary array allocations if clean
                    var needsScrubbing = false
                    for (element in originalTrace) {
                        val className = element.className
                        val methodName = element.methodName
                        if (suspiciousKeywords.any { className.contains(it) || methodName.contains(it) }) {
                            needsScrubbing = true
                            break
                        }
                    }

                    if (needsScrubbing) {
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
                }
                cause = cause.cause
            }
        }

        private fun bypassGhostInstanceDetection() {
            if (isBypassed) return
            isBypassed = true
            XposedBridge.log("TankeHook: Initializing Ultimate Exception scrubber...")

            // 1. Hook BaseDexClassLoader.findClass to catch ClassNotFoundException immediately when it's thrown
            // 它是 LoadedApk 内部抛出 ClassNotFoundException 的源头，这样在 Slog.e 打印前我们就把它洗干净了
            try {
                val baseDexClassLoaderClass = XposedHelpers.findClass("dalvik.system.BaseDexClassLoader", null)
                val findClassMethod = XposedHelpers.findMethodExact(
                    baseDexClassLoaderClass,
                    "findClass",
                    String::class.java
                )
                XposedBridge.hookMethod(findClassMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.hasThrowable()) {
                            scrubStackTrace(param.throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked BaseDexClassLoader.findClass successfully")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook BaseDexClassLoader: ${e.message}")
            }

            // 2. Hook LoadedApk.createOrUpdateClassLoaderLocked (for Ghost Instance NPE prevention)
            try {
                val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
                val createClassLoaderMethod = XposedHelpers.findMethodExact(
                    loadedApkClass,
                    "createOrUpdateClassLoaderLocked",
                    List::class.java
                )

                XposedBridge.hookMethod(createClassLoaderMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (param.hasThrowable()) {
                            scrubStackTrace(param.throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked LoadedApk.createOrUpdateClassLoaderLocked successfully")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook LoadedApk: ${e.message}")
            }

            // 3. Hook android.util.Slog.e and Log.e
            // 这样即便上面漏掉了，在即将写入 logcat 的那一刻也会被强行洗干净！
            try {
                val slogClass = XposedHelpers.findClass("android.util.Slog", null)
                val slogEMethod = XposedHelpers.findMethodExact(slogClass, "e", String::class.java, String::class.java, Throwable::class.java)
                XposedBridge.hookMethod(slogEMethod, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val throwable = param.args[2] as? Throwable
                        if (throwable != null) {
                            scrubStackTrace(throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked android.util.Slog.e successfully")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook android.util.Slog: ${e.message}")
            }

            try {
                val logClass = Log::class.java
                val logEMethod = XposedHelpers.findMethodExact(logClass, "e", String::class.java, String::class.java, Throwable::class.java)
                XposedBridge.hookMethod(logEMethod, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val throwable = param.args[2] as? Throwable
                        if (throwable != null) {
                            scrubStackTrace(throwable)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked android.util.Log.e successfully")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook android.util.Log: ${e.message}")
            }

            // 4. ActivityThread.attach
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
            } catch (e: Throwable) {
            }

            // 5. Throwable.getStackTrace (兜底防护)
            try {
                val getStackTraceMethod = Throwable::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(getStackTraceMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val elements = param.result as? Array<StackTraceElement> ?: return
                        if (elements.isEmpty()) return

                        var needsScrubbing = false
                        for (element in elements) {
                            val className = element.className
                            val methodName = element.methodName
                            if (suspiciousKeywords.any { className.contains(it) || methodName.contains(it) }) {
                                needsScrubbing = true
                                break
                            }
                        }
                        if (!needsScrubbing) return

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
            } catch (e: Throwable) {
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
