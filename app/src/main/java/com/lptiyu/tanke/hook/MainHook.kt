package com.lptiyu.tanke.hook

import android.content.pm.ApplicationInfo
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import java.lang.reflect.Field

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        private var isBypassed = false
        private var networkBootstrapInstalled = false
        private var classLoaderMonitorInstalled = false
        private var ossHttpDnsHooksInstalled = false
        private var okhttpHooksInstalled = false
        private var trustManagerHooksInstalled = false
        private const val GHOST_MARKER = "\$\$ghost_detect\$\$"

        private val permissiveHostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }

        /** 重入锁：防止 getStackTrace() hook 内部触发递归调用 */
        private val isProcessing = ThreadLocal.withInitial { false }

        /** StackTraceElement.declaringClass 字段，用于字段级清洗 */
        private val declClassField: Field? by lazy {
            try {
                StackTraceElement::class.java.getDeclaredField("declaringClass").apply {
                    isAccessible = true
                }
            } catch (_: Throwable) { null }
        }

        private val methodNameField: Field? by lazy {
            try {
                StackTraceElement::class.java.getDeclaredField("methodName").apply {
                    isAccessible = true
                }
            } catch (_: Throwable) { null }
        }

        // ═══════════════════════════════════════════════════════════
        //  检测与清洗逻辑
        // ═══════════════════════════════════════════════════════════

        /**
         * 判断类名是否属于 hook 框架。
         * 壳主要检查 className.contains("xposed")，
         * 但我们额外覆盖所有已知框架特征。
         */
        private fun isSuspiciousClassName(className: String): Boolean {
            val lower = className.lowercase()
            if (lower.contains("xposed")) return true
            if (lower.contains("lsposed")) return true
            if (lower.contains("lspd")) return true
            if (lower.contains("sandhook")) return true
            if (lower.contains("epic")) return true
            if (lower.contains("pine")) return true

            if (className.endsWith(".HookBridge") || className == "HookBridge") return true
            if (className.startsWith("LSPHooker")) return true

            return false
        }

        /** 判断单个栈帧是否属于 hook 框架 */
        private fun isSuspiciousFrame(element: StackTraceElement): Boolean {
            val className = element.className
            val methodName = element.methodName

            if (isSuspiciousClassName(className)) return true

            // 混淆后的回调类：短类名 + callback
            if (className.length <= 2 && methodName == "callback") return true
            if (methodName == "invokeOriginalMethod") return true
            if (methodName == "handleHookedMethod") return true

            return false
        }

        /**
         * 直接修改 StackTraceElement 的 declaringClass 字段。
         * 这是防御壳通过 JNI GetObjectField 直接读取字段值的最后一道防线。
         */
        private fun sanitizeElements(elements: Array<StackTraceElement>) {
            val field = declClassField ?: return
            for (element in elements) {
                try {
                    val cls = field.get(element) as? String ?: continue
                    if (isSuspiciousClassName(cls)) {
                        field.set(element, "android.os.Handler")
                        methodNameField?.set(element, "dispatchMessage")
                    }
                } catch (_: Throwable) {}
            }
        }

        /**
         * 清洗栈帧数组：移除所有 hook 框架痕迹 + 修改残留元素的字段。
         * @return 清洗后的数组，如果无需清洗则返回 null
         */
        private fun cleanAndSanitize(elements: Array<StackTraceElement>): Array<StackTraceElement>? {
            if (elements.isEmpty()) return null

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

            val result = cleanTrace.toTypedArray()
            // 额外安全：修改保留元素的字段（防止 JNI 直接读取）
            sanitizeElements(result)
            return result
        }

        // ═══════════════════════════════════════════════════════════
        //  Hook 安装
        // ═══════════════════════════════════════════════════════════

        private fun installAllHooks() {
            if (isBypassed) return
            isBypassed = true
            XposedBridge.log("TankeHook: Installing hooks...")

            installUnsafeHook()
            installGhostInterceptor()
            installStackTraceElementHooks()
            installThrowableGetStackTraceHook()
            installThreadGetStackTraceHook()
            installThreadGetAllStackTracesHook()
            installVMStackHook()
        }

        // ── Hook 0: Unsafe.allocateInstance ────────────────────────
        private fun installUnsafeHook() {
            try {
                val unsafeClass = Class.forName("sun.misc.Unsafe")
                val allocMethod = unsafeClass.getDeclaredMethod("allocateInstance", Class::class.java)
                XposedBridge.hookMethod(allocMethod, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result ?: return
                        if (result.javaClass.name != "android.app.LoadedApk") return
                        try {
                            XposedHelpers.setObjectField(result, "mPackageName", GHOST_MARKER)
                            val appInfo = ApplicationInfo()
                            appInfo.packageName = GHOST_MARKER
                            appInfo.processName = GHOST_MARKER
                            appInfo.sourceDir = "/dev/null"
                            appInfo.dataDir = "/dev/null"
                            appInfo.nativeLibraryDir = "/dev/null"
                            appInfo.targetSdkVersion = 34
                            XposedHelpers.setObjectField(result, "mApplicationInfo", appInfo)
                        } catch (_: Throwable) {}
                    }
                })
                XposedBridge.log("TankeHook: Hooked Unsafe.allocateInstance")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook Unsafe: ${e.message}")
            }
        }

        // ── Hook 1: createOrUpdateClassLoaderLocked ────────────────
        private fun installGhostInterceptor() {
            try {
                val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
                val method = XposedHelpers.findMethodExact(
                    loadedApkClass, "createOrUpdateClassLoaderLocked", List::class.java
                )
                XposedBridge.hookMethod(method, object : XC_MethodHook(10000) {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            val pkg = XposedHelpers.getObjectField(param.thisObject, "mPackageName")
                            if (pkg == null || pkg == GHOST_MARKER) {
                                param.throwable = NullPointerException(
                                    "Attempt to invoke virtual method on a null object reference"
                                )
                            }
                        } catch (_: Throwable) {
                            param.throwable = NullPointerException(
                                "Attempt to invoke virtual method on a null object reference"
                            )
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked createOrUpdateClassLoaderLocked")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }
        }

        // ── Hook 2: StackTraceElement.getClassName / toString ──────
        // 壳在 JNI_OnLoad 中遍历 StackTraceElement[] 并调用 getClassName()
        // 检查是否包含 "xposed"。这是最关键的拦截点。
        private fun installStackTraceElementHooks() {
            // getClassName()
            try {
                val m = StackTraceElement::class.java.getDeclaredMethod("getClassName")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val name = param.result as? String ?: return
                        if (isSuspiciousClassName(name)) {
                            param.result = "android.os.Handler"
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked StackTraceElement.getClassName()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }

            // toString()
            try {
                val m = StackTraceElement::class.java.getDeclaredMethod("toString")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val str = param.result as? String ?: return
                        val lower = str.lowercase()
                        if (lower.contains("xposed") || lower.contains("lsposed") ||
                            lower.contains("hookbridge") || lower.contains("lsphooker")
                        ) {
                            param.result = "android.os.Handler.dispatchMessage(Handler.java:106)"
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked StackTraceElement.toString()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }

            // getMethodName()
            try {
                val m = StackTraceElement::class.java.getDeclaredMethod("getMethodName")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val name = param.result as? String ?: return
                        if (name == "handleHookedMethod" || name == "invokeOriginalMethod" || name == "callback") {
                            param.result = "dispatchMessage"
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked StackTraceElement.getMethodName()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }
        }

        // ── Hook 3: Throwable.getStackTrace() ──────────────────────
        private fun installThrowableGetStackTraceHook() {
            try {
                val m = Throwable::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            @Suppress("UNCHECKED_CAST")
                            val elements = param.result as? Array<StackTraceElement> ?: return
                            val cleaned = cleanAndSanitize(elements) ?: return
                            param.result = cleaned
                            try { (param.thisObject as? Throwable)?.stackTrace = cleaned } catch (_: Throwable) {}
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Throwable.getStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }
        }

        // ── Hook 4: Thread.getStackTrace() ─────────────────────────
        private fun installThreadGetStackTraceHook() {
            try {
                val m = Thread::class.java.getDeclaredMethod("getStackTrace")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            @Suppress("UNCHECKED_CAST")
                            val elements = param.result as? Array<StackTraceElement> ?: return
                            val cleaned = cleanAndSanitize(elements) ?: return
                            param.result = cleaned
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Thread.getStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }
        }

        // ── Hook 5: Thread.getAllStackTraces() ──────────────────────
        private fun installThreadGetAllStackTracesHook() {
            try {
                val m = Thread::class.java.getDeclaredMethod("getAllStackTraces")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    @Suppress("UNCHECKED_CAST")
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            val map = param.result as? Map<Thread, Array<StackTraceElement>> ?: return
                            var changed = false
                            val cleaned = LinkedHashMap<Thread, Array<StackTraceElement>>(map.size)
                            for ((thread, elements) in map) {
                                val c = cleanAndSanitize(elements)
                                if (c != null) { cleaned[thread] = c; changed = true }
                                else cleaned[thread] = elements
                            }
                            if (changed) param.result = cleaned
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked Thread.getAllStackTraces()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed: ${e.message}")
            }
        }

        // ── Hook 6: VMStack.getThreadStackTrace() ──────────────────
        // 壳可能绕过 Thread.getStackTrace()，直接通过 JNI 调用
        // dalvik.system.VMStack.getThreadStackTrace(Thread) 获取原始堆栈。
        private fun installVMStackHook() {
            try {
                val vmStackClass = XposedHelpers.findClass("dalvik.system.VMStack", null)
                val m = vmStackClass.getDeclaredMethod("getThreadStackTrace", Thread::class.java)
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        if (isProcessing.get()) return
                        isProcessing.set(true)
                        try {
                            @Suppress("UNCHECKED_CAST")
                            val elements = param.result as? Array<StackTraceElement> ?: return
                            val cleaned = cleanAndSanitize(elements)
                            if (cleaned != null) param.result = cleaned
                            else sanitizeElements(elements) // 即使不删除帧，也修改字段
                        } finally {
                            isProcessing.set(false)
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked VMStack.getThreadStackTrace()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook VMStack: ${e.message}")
            }
        }

        // ── Network hooks: for traffic capture only in target app ─────────
        private fun installNetworkCaptureHooks(classLoader: ClassLoader?) {
            if (networkBootstrapInstalled || classLoader == null) return
            networkBootstrapInstalled = true
            XposedBridge.log("TankeHook: Installing network capture hooks...")

            installTrustManagerBypass()
            installOssHttpDnsBypass(classLoader)
            installOkHttpPinningBypass(classLoader)
            installClassLoaderMonitor()
        }

        private fun installClassLoaderMonitor() {
            if (classLoaderMonitorInstalled) return
            classLoaderMonitorInstalled = true
            try {
                XposedHelpers.findAndHookMethod(
                    ClassLoader::class.java,
                    "loadClass",
                    String::class.java,
                    object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            val name = param.args[0] as? String ?: return
                            val loader = param.thisObject as? ClassLoader ?: return
                            if (!ossHttpDnsHooksInstalled && name.startsWith("com.alibaba.sdk.android.oss")) {
                                installOssHttpDnsBypass(loader)
                            }
                            if (!okhttpHooksInstalled && name.startsWith("okhttp3")) {
                                installOkHttpPinningBypass(loader)
                            }
                        }
                    }
                )
                XposedBridge.log("TankeHook: Hooked ClassLoader.loadClass for delayed network hooks")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: ClassLoader monitor hook failed: ${e.message}")
            }
        }

        private fun installOssHttpDnsBypass(classLoader: ClassLoader) {
            if (ossHttpDnsHooksInstalled) return
            try {
                XposedHelpers.findAndHookMethod(
                    "com.alibaba.sdk.android.oss.ClientConfiguration",
                    classLoader,
                    "isHttpDnsEnable",
                    object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            param.result = false
                        }
                    }
                )

                XposedHelpers.findAndHookMethod(
                    "com.alibaba.sdk.android.oss.ClientConfiguration",
                    classLoader,
                    "setHttpDnsEnable",
                    Boolean::class.javaPrimitiveType,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.args[0] = false
                        }
                    }
                )

                XposedHelpers.findAndHookMethod(
                    "com.alibaba.sdk.android.oss.internal.InternalRequestOperation",
                    classLoader,
                    "checkIfHttpDnsAvailable",
                    Boolean::class.javaPrimitiveType,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = false
                        }
                    }
                )

                // 直接兜底域名校验，处理代理证书 SAN 不匹配导致的 Hostname not verified。
                XposedHelpers.findAndHookConstructor(
                    "com.alibaba.sdk.android.oss.internal.InternalRequestOperation",
                    classLoader,
                    android.content.Context::class.java,
                    java.net.URI::class.java,
                    XposedHelpers.findClass("com.alibaba.sdk.android.oss.common.auth.OSSCredentialProvider", classLoader),
                    XposedHelpers.findClass("com.alibaba.sdk.android.oss.ClientConfiguration", classLoader),
                    object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            try {
                                val client = XposedHelpers.getObjectField(param.thisObject, "innerClient")
                                val builder = XposedHelpers.callMethod(client, "newBuilder")
                                XposedHelpers.callMethod(builder, "hostnameVerifier", permissiveHostnameVerifier)
                                val rebuilt = XposedHelpers.callMethod(builder, "build")
                                XposedHelpers.setObjectField(param.thisObject, "innerClient", rebuilt)
                            } catch (_: Throwable) {
                            }
                        }
                    }
                )

                ossHttpDnsHooksInstalled = true
                XposedBridge.log("TankeHook: OSS HttpDNS + hostname hooks installed")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: OSS hooks delayed, class not ready: ${e.message}")
            }
        }

        private fun installOkHttpPinningBypass(classLoader: ClassLoader) {
            if (okhttpHooksInstalled) return
            try {
                val certPinnerClass = XposedHelpers.findClass("okhttp3.CertificatePinner", classLoader)

                val checkList = certPinnerClass.getDeclaredMethod("check", String::class.java, List::class.java)
                XposedBridge.hookMethod(checkList, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                    }
                })

                val certArrayClass = Class.forName("[Ljava.security.cert.Certificate;")
                val checkArray = certPinnerClass.getDeclaredMethod("check", String::class.java, certArrayClass)
                XposedBridge.hookMethod(checkArray, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                    }
                })

                val defaultPinner = certPinnerClass.getDeclaredField("DEFAULT").get(null)
                XposedHelpers.findAndHookMethod(
                    "okhttp3.OkHttpClient\$Builder",
                    classLoader,
                    "certificatePinner",
                    certPinnerClass,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.args[0] = defaultPinner
                        }
                    }
                )

                try {
                    XposedHelpers.findAndHookMethod(
                        "okhttp3.internal.tls.OkHostnameVerifier",
                        classLoader,
                        "verify",
                        String::class.java,
                        javax.net.ssl.SSLSession::class.java,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = true
                            }
                        }
                    )
                } catch (_: Throwable) {
                }

                okhttpHooksInstalled = true
                XposedBridge.log("TankeHook: OkHttp pinning + hostname hooks installed")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: OkHttp hooks delayed, class not ready: ${e.message}")
            }
        }

        private fun installTrustManagerBypass() {
            if (trustManagerHooksInstalled) return
            var installed = false

            // Android Conscrypt 常见证书链校验入口
            try {
                val trustManagerImplClass = Class.forName("com.android.org.conscrypt.TrustManagerImpl")
                for (method in trustManagerImplClass.declaredMethods) {
                    if (method.name != "verifyChain") continue
                    XposedBridge.hookMethod(method, object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            if (param.args.isNotEmpty()) {
                                param.result = param.args[0]
                            }
                        }
                    })
                }
                installed = true
                XposedBridge.log("TankeHook: Hooked TrustManagerImpl.verifyChain(..)")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: TrustManagerImpl hook failed: ${e.message}")
            }

            // 兜底替换默认 HostnameVerifier，覆盖 HttpsURLConnection 默认校验。
            try {
                val m = javax.net.ssl.HttpsURLConnection::class.java.getDeclaredMethod("getDefaultHostnameVerifier")
                XposedBridge.hookMethod(m, object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = permissiveHostnameVerifier
                    }
                })
                installed = true
                XposedBridge.log("TankeHook: Hooked HttpsURLConnection.getDefaultHostnameVerifier()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: HttpsURLConnection hostname hook failed: ${e.message}")
            }

            trustManagerHooksInstalled = installed
        }
    }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        NativeHelper.install(startupParam.modulePath)
        installAllHooks()
    }

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") return
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")
        installNetworkCaptureHooks(lpparam.classLoader)
    }
}
