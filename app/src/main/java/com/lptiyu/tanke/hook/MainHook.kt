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
        private var adHooksInstalled = false
        private var splashAdHookInstalled = false
        private val hookedHostnameVerifierClasses = HashSet<String>()
        private val isInstallingNetworkHooks = ThreadLocal.withInitial { false }
        private const val GHOST_MARKER = "\$\$ghost_detect\$\$"

        // ═══════════════════════════════════════════════════════════
        //  SharedPreferences 开关（通过 XSharedPreferences 读取）
        //  在 handleLoadPackage 时初始化，之后只读不写
        // ═══════════════════════════════════════════════════════════
        private var prefBypassSsl      = true
        private var prefDisableHttpdns = true
        private var prefDisableAds     = true
        private var prefSkipSplashAd   = true
        private var prefAntiDetect     = true
        private var prefVerboseLog     = false

        @Suppress("DEPRECATION")
        private fun loadPrefs() {
            try {
                val xsp = de.robv.android.xposed.XSharedPreferences(
                    "com.lptiyu.tanke.hook",
                    SettingsActivity.PREFS_NAME
                )
                xsp.makeWorldReadable()
                xsp.reload()
                prefBypassSsl      = xsp.getBoolean(SettingsActivity.KEY_BYPASS_SSL,         true)
                prefDisableHttpdns = xsp.getBoolean(SettingsActivity.KEY_DISABLE_HTTPDNS,    true)
                prefDisableAds     = xsp.getBoolean(SettingsActivity.KEY_DISABLE_ADS,        true)
                prefSkipSplashAd   = xsp.getBoolean(SettingsActivity.KEY_SKIP_SPLASH_AD,     true)
                prefAntiDetect     = xsp.getBoolean(SettingsActivity.KEY_ANTI_DETECT,        true)
                prefVerboseLog     = xsp.getBoolean(SettingsActivity.KEY_VERBOSE_LOG,        false)
                XposedBridge.log("TankeHook: Prefs loaded — ssl=$prefBypassSsl httpdns=$prefDisableHttpdns ads=$prefDisableAds splash=$prefSkipSplashAd antiDetect=$prefAntiDetect verbose=$prefVerboseLog")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to load prefs (using defaults): ${e.message}")
            }
        }

        private fun vlog(msg: String) {
            if (prefVerboseLog) XposedBridge.log("TankeHook[V]: $msg")
        }

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

            // 反检测 Hooks 在 Zygote 阶段安装，不受开关约束（因为 prefs 此时还未读取）
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
            XposedBridge.log("TankeHook: Installing network capture hooks (ssl=$prefBypassSsl httpdns=$prefDisableHttpdns)...")

            if (prefBypassSsl) {
                installTrustManagerBypass()
            }
            if (prefBypassSsl || prefDisableHttpdns) {
                installOssHttpDnsBypass(classLoader)
            }
            if (prefBypassSsl) {
                installOkHttpPinningBypass(classLoader)
            }
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
                            if (isInstallingNetworkHooks.get()) return

                            val name = param.args[0] as? String ?: return
                            val loader = param.thisObject as? ClassLoader ?: return
                            val loadedClass = param.result as? Class<*> ?: return

                            isInstallingNetworkHooks.set(true)
                            try {
                                if (prefBypassSsl) {
                                    installHostnameVerifierBypassForClass(name, loadedClass)
                                }

                                if (prefDisableHttpdns && !ossHttpDnsHooksInstalled &&
                                        name.startsWith("com.alibaba.sdk.android.oss")) {
                                    installOssHttpDnsBypass(loader)
                                }
                                if (prefBypassSsl && !okhttpHooksInstalled && name.startsWith("okhttp3")) {
                                    installOkHttpPinningBypass(loader)
                                }
                                if ((prefDisableAds || prefSkipSplashAd) && !adHooksInstalled &&
                                        (name.startsWith("com.yfanads") ||
                                         name.startsWith("com.beizi") ||
                                         name.startsWith("com.kwad") ||
                                         name.startsWith("com.bytedance.sdk.openadsdk"))) {
                                    installAdSdkHooks(loader)
                                }
                                if (prefSkipSplashAd && !splashAdHookInstalled &&
                                        (name == "com.lptiyu.tanke.activities.splash.SplashActivity" ||
                                         name == "com.yfanads.android.core.splash.YFAdSplashAds")) {
                                    installSplashAdHooks(loader)
                                }
                            } finally {
                                isInstallingNetworkHooks.set(false)
                            }
                        }
                    }
                )
                XposedBridge.log("TankeHook: Hooked ClassLoader.loadClass for delayed network hooks")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: ClassLoader monitor hook failed: ${e.message}")
            }
        }

        private fun installHostnameVerifierBypassForClass(className: String, clazz: Class<*>) {
            if (hookedHostnameVerifierClasses.contains(className)) return
            if (!javax.net.ssl.HostnameVerifier::class.java.isAssignableFrom(clazz)) return

            try {
                val verifyMethod = clazz.getDeclaredMethod(
                    "verify",
                    String::class.java,
                    javax.net.ssl.SSLSession::class.java
                )
                XposedBridge.hookMethod(verifyMethod, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = true
                    }
                })
                hookedHostnameVerifierClasses.add(className)
                XposedBridge.log("TankeHook: Hooked HostnameVerifier.verify for $className")
            } catch (_: Throwable) {
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

        // ── Ad SDK Hooks ──────────────────────────────────────────
        /**
         * 拦截各广告 SDK 的初始化方法，阻止其完成初始化。
         * 由 ClassLoader.loadClass 监听器触发，在相关 SDK 类首次加载时安装。
         */
        private fun installAdSdkHooks(classLoader: ClassLoader) {
            if (adHooksInstalled) return
            adHooksInstalled = true

            XposedBridge.log("TankeHook: Installing Ad SDK hooks (disableAds=$prefDisableAds)...")

            // — YFAds ——————————————————————————————————————————
            if (prefDisableAds) {
                try {
                    val yfMgrClass = XposedHelpers.findClass("com.yfanads.android.YFAdsManager", classLoader)
                    // 查找所有名为 init 的方法并 hook（避免依赖 YFAdsConfig 的类引用）
                    var hooked = false
                    for (method in yfMgrClass.declaredMethods) {
                        if (method.name == "init") {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    vlog("YFAdsManager.init() blocked")
                                    param.result = null
                                }
                            })
                            hooked = true
                        }
                    }
                    if (hooked) XposedBridge.log("TankeHook: Hooked YFAdsManager.init()")
                    else XposedBridge.log("TankeHook: YFAdsManager.init method not found")
                } catch (e: Throwable) {
                    XposedBridge.log("TankeHook: YFAdsManager hook failed: ${e.message}")
                }

                try {
                    XposedHelpers.findAndHookMethod(
                        "com.yfanads.android.YFAdsManager", classLoader,
                        "isInitSuc",
                        object : XC_MethodHook() {
                            override fun afterHookedMethod(param: MethodHookParam) {
                                vlog("YFAdsManager.isInitSuc() → false")
                                param.result = false
                            }
                        }
                    )
                } catch (_: Throwable) {}
            }

            // — BeiZi 北智融合广告 ─────────────────────────────────
            if (prefDisableAds) {
                try {
                    XposedHelpers.findAndHookMethod(
                        "com.beizi.fusion.BeiZis", classLoader,
                        "init",
                        android.content.Context::class.java,
                        String::class.java,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                vlog("BeiZis.init() blocked")
                                param.result = null
                            }
                        }
                    )
                    XposedBridge.log("TankeHook: Hooked BeiZis.init()")
                } catch (e: Throwable) {
                    XposedBridge.log("TankeHook: BeiZis.init hook failed: ${e.message}")
                }
                try {
                    XposedHelpers.findAndHookMethod(
                        "com.beizi.fusion.BeiZis", classLoader,
                        "asyncInit",
                        android.content.Context::class.java,
                        String::class.java,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                vlog("BeiZis.asyncInit() blocked")
                                param.result = null
                            }
                        }
                    )
                } catch (_: Throwable) {}
            }

            // — 快手 KsAdSDK ───────────────────────────────────────
            if (prefDisableAds) {
                try {
                    val ksConfigClass = XposedHelpers.findClass(
                        "com.kwad.sdk.api.SdkConfig", classLoader
                    )
                    XposedHelpers.findAndHookMethod(
                        "com.kwad.sdk.api.KsAdSDK", classLoader,
                        "init",
                        android.content.Context::class.java,
                        ksConfigClass,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                vlog("KsAdSDK.init() blocked")
                                param.result = false
                            }
                        }
                    )
                    XposedBridge.log("TankeHook: Hooked KsAdSDK.init()")
                } catch (e: Throwable) {
                    XposedBridge.log("TankeHook: KsAdSDK.init hook failed: ${e.message}")
                }
                try {
                    XposedHelpers.findAndHookMethod(
                        "com.kwad.sdk.api.KsAdSDK", classLoader,
                        "start",
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                vlog("KsAdSDK.start() blocked")
                                param.result = null
                            }
                        }
                    )
                } catch (_: Throwable) {}
            }

            // — 字节跳动 Pangle/TTAdSdk ────────────────────────────
            if (prefDisableAds) {
                try {
                    val clazz = XposedHelpers.findClass(
                        "com.bytedance.sdk.openadsdk.TTAdSdk", classLoader
                    )
                    for (method in clazz.declaredMethods) {
                        if (method.name == "init" || method.name == "start") {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    vlog("TTAdSdk.${method.name}() blocked")
                                    param.result = null
                                }
                            })
                        }
                    }
                    XposedBridge.log("TankeHook: Hooked TTAdSdk init/start")
                } catch (e: Throwable) {
                    XposedBridge.log("TankeHook: TTAdSdk hook skipped (may not be present): ${e.message}")
                }
            }
        }

        /**
         * 拦截 SplashActivity 中的广告展示方法，跳过开屏广告直接进入主界面。
         * 由 ClassLoader.loadClass 监听器触发，在 SplashActivity 首次加载时安装。
         *
         * 策略：
         * - 不拦截 initSdk()（它还负责初始化 token/网络等关键功能）
         * - 拦截 YFAdSplashAds.showAds() 并立即触发 onAdClosed() 回调，
         *   模拟广告正常关闭，使 SplashActivity 继续执行跳转逻辑
         * - 同时拦截 fetchAd() 阻止广告请求
         */
        private fun installSplashAdHooks(classLoader: ClassLoader) {
            if (splashAdHookInstalled) return
            splashAdHookInstalled = true

            XposedBridge.log("TankeHook: Installing SplashActivity ad hooks...")

            // Hook YFAdSplashAds.showAds() — 核心：立即触发 onAdClosed 回调跳过广告
            try {
                XposedHelpers.findAndHookMethod(
                    "com.yfanads.android.core.splash.YFAdSplashAds", classLoader,
                    "showAds",
                    android.app.Activity::class.java,
                    android.view.ViewGroup::class.java,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            vlog("YFAdSplashAds.showAds() intercepted, triggering onAdClosed()")
                            param.result = null  // 阻止广告展示
                            // 立即通过 listener 触发广告关闭回调，使 SplashActivity 执行跳转
                            try {
                                val listener = XposedHelpers.getObjectField(param.thisObject, "listener")
                                if (listener != null) {
                                    XposedHelpers.callMethod(listener, "onAdClosed")
                                    vlog("YFAdSplashAds: onAdClosed() triggered on listener: ${listener.javaClass.name}")
                                }
                            } catch (e: Throwable) {
                                XposedBridge.log("TankeHook: Failed to trigger onAdClosed: ${e.message}")
                            }
                        }
                    }
                )
                XposedBridge.log("TankeHook: Hooked YFAdSplashAds.showAds()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: YFAdSplashAds.showAds hook failed: ${e.message}")
            }

            // Hook SplashActivity.fetchAd() — 阻止广告请求网络（次要防线）
            try {
                val splashClass = XposedHelpers.findClass(
                    "com.lptiyu.tanke.activities.splash.SplashActivity", classLoader
                )
                val fetchAdMethod = splashClass.getDeclaredMethod("fetchAd", String::class.java)
                XposedBridge.hookMethod(fetchAdMethod, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        vlog("SplashActivity.fetchAd() skipped")
                        param.result = null
                    }
                })
                XposedBridge.log("TankeHook: Hooked SplashActivity.fetchAd()")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: fetchAd hook failed: ${e.message}")
            }
        }

        private fun installTrustManagerBypass() {            if (trustManagerHooksInstalled) return
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
        loadPrefs()
        installNetworkCaptureHooks(lpparam.classLoader)
    }
}
