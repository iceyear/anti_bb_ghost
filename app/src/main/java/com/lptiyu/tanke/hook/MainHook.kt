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

        /**
         * 重入锁：防止 getStackTrace() hook 内部触发递归调用
         */
        private val isProcessing = ThreadLocal.withInitial { false }

        /**
         * 判断单个栈帧是否属于 hook 框架的痕迹。
         * 涵盖 LSPosed、Xposed、EdXposed、SandHook、Pine 等主流框架。
         */
        private fun isSuspiciousFrame(element: StackTraceElement): Boolean {
            val className = element.className
            val methodName = element.methodName

            // 主流 hook 框架的明文类名特征
            if (className.contains("org.lsposed") ||
                className.contains("de.robv.android.xposed") ||
                className.contains("LSPHooker") ||
                className.contains("com.elder.xposed") ||
                className.contains("SandHook") ||
                className.contains("EdXposed") ||
                className.contains("me.weishu.epic") ||
                className.contains("top.canyie.pine") ||
                className.contains("com.swift.sandhook") ||
                className.contains("lspd")
            ) {
                return true
            }

            // 混淆后的 HookBridge（如 KmkyjghNEh.FrHZn.faUePQsyDyyx.HookBridge）
            if (className.endsWith(".HookBridge") || className == "HookBridge") {
                return true
            }

            // 混淆后的回调类：短类名 + callback 方法（如 class=J, method=callback）
            if (className.length <= 2 && methodName == "callback") {
                return true
            }

            // invokeOriginalMethod 是 LSPosed bridge 的核心调用
            if (methodName == "invokeOriginalMethod") {
                return true
            }

            return false
        }

        /**
         * 清洗栈帧数组：移除所有 hook 框架痕迹，
         * 同时移除紧随其后的反射 Method.invoke 帧（用于调用原方法的桥接层）。
         * @return 清洗后的数组，如果无需清洗则返回 null
         */
        private fun cleanStackTrace(elements: Array<StackTraceElement>): Array<StackTraceElement>? {
            if (elements.isEmpty()) return null

            // 快速扫描：如果没有可疑帧则直接跳过，避免不必要的内存分配
            var needsScrubbing = false
            for (element in elements) {
                if (isSuspiciousFrame(element)) {
                    needsScrubbing = true
                    break
                }
            }
            if (!needsScrubbing) return null

            val cleanTrace = mutableListOf<StackTraceElement>()
            var skipNextMethodInvoke = false

            for (element in elements) {
                if (isSuspiciousFrame(element)) {
                    skipNextMethodInvoke = true
                    continue
                }

                // hook 框架通过反射 Method.invoke 调用原方法，一并剔除
                if (skipNextMethodInvoke &&
                    element.className == "java.lang.reflect.Method" &&
                    element.methodName == "invoke"
                ) {
                    skipNextMethodInvoke = false
                    continue
                }

                skipNextMethodInvoke = false
                cleanTrace.add(element)
            }

            return if (cleanTrace.size != elements.size) cleanTrace.toTypedArray() else null
        }

        /**
         * 安装所有堆栈清洗 hook。
         * 策略：不 hook 任何会干扰 App 正常初始化的系统方法（如 findClass、createOrUpdateClassLoaderLocked），
         * 只在壳读取堆栈的出口处拦截并清洗。
         */
        private fun bypassGhostInstanceDetection() {
            if (isBypassed) return
            isBypassed = true
            XposedBridge.log("TankeHook: Initializing stack trace scrubber...")

            // ═══════════════════════════════════════════════════════════
            // Hook 0: LoadedApk.createOrUpdateClassLoaderLocked — 幽灵对象拦截器
            // 壳使用 Unsafe.allocateInstance 创建全空的"幽灵" LoadedApk 对象，
            // 然后调用此方法引爆异常并检查堆栈中的 hook 痕迹。
            // 问题：LSPosed 内置 hook 此方法，native HookBridge 处理全空对象
            // 时会触发 SIGSEGV（null+0x88c）。
            // 解决：在 beforeHookedMethod 中（priority 最高，先于 LSPosed 的 bridge）
            // 检测幽灵对象（mPackageName==null），直接抛出干净的 NPE，
            // 阻止调用进入 native bridge。
            // ═══════════════════════════════════════════════════════════
            try {
                val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
                val createCLMethod = XposedHelpers.findMethodExact(
                    loadedApkClass,
                    "createOrUpdateClassLoaderLocked",
                    List::class.java
                )
                XposedBridge.hookMethod(createCLMethod, object : XC_MethodHook(10000) {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            // 检查关键字段：幽灵对象所有字段均为 null
                            val mPackageName = XposedHelpers.getObjectField(param.thisObject, "mPackageName")
                            if (mPackageName == null) {
                                // 幽灵对象！抛出 NPE 阻止进入 native bridge
                                // getStackTrace() hook 会在壳读取时清洗此异常的堆栈
                                param.throwable = NullPointerException(
                                    "Attempt to invoke virtual method on a null object reference"
                                )
                                return
                            }
                        } catch (_: Throwable) {
                            // 字段访问失败也说明对象异常，同样拦截
                            param.throwable = NullPointerException(
                                "Attempt to invoke virtual method on a null object reference"
                            )
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked createOrUpdateClassLoaderLocked (ghost interceptor)")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook createOrUpdateClassLoaderLocked: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 1: Throwable.getStackTrace() — 核心防线
            // 壳通过 exception.getStackTrace() 读取堆栈并扫描 hook 痕迹，
            // 在返回结果前清洗即可欺骗检测。
            // 同时更新 Throwable 内部的 stackTrace 字段，
            // 确保后续 printStackTrace() 也返回干净结果。
            // ═══════════════════════════════════════════════════════════
            try {
                val getStackTraceMethod = Throwable::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(getStackTraceMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        // 重入保护
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val elements = param.result as? Array<*> ?: return
                            @Suppress("UNCHECKED_CAST")
                            val stackElements = elements as? Array<StackTraceElement> ?: return
                            val cleaned = cleanStackTrace(stackElements) ?: return
                            param.result = cleaned
                            // 持久化到 Throwable 内部，使 printStackTrace() 同样干净
                            try {
                                (param.thisObject as? Throwable)?.stackTrace = cleaned
                            } catch (_: Throwable) {
                            }
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Throwable.getStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Throwable.getStackTrace: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 2: Thread.getStackTrace() — 辅助防线
            // 壳可能通过 Thread.currentThread().getStackTrace() 检查当前调用栈
            // ═══════════════════════════════════════════════════════════
            try {
                val threadGetStackTrace = Thread::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(threadGetStackTrace, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val elements = param.result as? Array<*> ?: return
                            @Suppress("UNCHECKED_CAST")
                            val stackElements = elements as? Array<StackTraceElement> ?: return
                            val cleaned = cleanStackTrace(stackElements) ?: return
                            param.result = cleaned
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Thread.getStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Thread.getStackTrace: ${e.message}")
            }

            // ═══════════════════════════════════════════════════════════
            // Hook 3: Thread.getAllStackTraces() — 补充防线
            // 壳可能枚举所有线程的堆栈来检测 hook
            // ═══════════════════════════════════════════════════════════
            try {
                val getAllStackTraces = Thread::class.java.getDeclaredMethod("getAllStackTraces")
                XposedBridge.hookMethod(getAllStackTraces, object : XC_MethodHook() {
                    @Suppress("UNCHECKED_CAST")
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val map = param.result as? Map<Thread, Array<StackTraceElement>> ?: return
                            var anyChanged = false
                            val cleanedMap = LinkedHashMap<Thread, Array<StackTraceElement>>(map.size)
                            for ((thread, elements) in map) {
                                val cleaned = cleanStackTrace(elements)
                                if (cleaned != null) {
                                    cleanedMap[thread] = cleaned
                                    anyChanged = true
                                } else {
                                    cleanedMap[thread] = elements
                                }
                            }
                            if (anyChanged) {
                                param.result = cleanedMap
                            }
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Thread.getAllStackTraces()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Thread.getAllStackTraces: ${e.message}")
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
