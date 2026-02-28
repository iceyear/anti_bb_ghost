package com.lptiyu.tanke.hook

import android.content.pm.ApplicationInfo
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class MainHook : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        private var isBypassed = false

        private fun bypassGhostInstanceDetection() {
            if (isBypassed) return
            isBypassed = true
            XposedBridge.log("TankeHook: Initializing Ghost Instance & AppComponentFactory trap bypass...")

            // Hook LoadedApk.createOrUpdateClassLoaderLocked
            try {
                val loadedApkClass = XposedHelpers.findClass("android.app.LoadedApk", null)
                val createClassLoaderMethod = XposedHelpers.findMethodExact(
                    loadedApkClass,
                    "createOrUpdateClassLoaderLocked",
                    List::class.java
                )

                XposedBridge.hookMethod(createClassLoaderMethod, object : XC_MethodHook() {
                    @Throws(Throwable::class)
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val loadedApk = param.thisObject
                        if (loadedApk == null) return

                        // 1. Ghost Instance Prevention
                        val appInfo = XposedHelpers.getObjectField(loadedApk, "mApplicationInfo") as? ApplicationInfo
                        if (appInfo == null) {
                            XposedBridge.log("TankeHook: Detected Ghost LoadedApk instance! Intercepting crash.")
                            param.result = null
                            return
                        }

                        // 2. AppComponentFactory Trap Prevention
                        val componentFactory = appInfo.appComponentFactory
                        if (componentFactory != null && (componentFactory == "com.lptiyu.tanke.lp" || componentFactory.contains("tanke"))) {
                            XposedBridge.log("TankeHook: Detected trap appComponentFactory: $componentFactory. Nullifying to prevent ClassNotFoundException.")
                            XposedHelpers.setObjectField(appInfo, "appComponentFactory", null)
                            param.setObjectExtra("originalFactory", componentFactory)
                        }
                    }

                    @Throws(Throwable::class)
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val originalFactory = param.getObjectExtra("originalFactory") as? String
                        if (originalFactory != null) {
                            val loadedApk = param.thisObject
                            val appInfo = XposedHelpers.getObjectField(loadedApk, "mApplicationInfo") as? ApplicationInfo
                            if (appInfo != null) {
                                XposedHelpers.setObjectField(appInfo, "appComponentFactory", originalFactory)
                                XposedBridge.log("TankeHook: Restored trap appComponentFactory: $originalFactory")
                            }
                        }
                    }
                })
                XposedBridge.log("TankeHook: Hooked LoadedApk.createOrUpdateClassLoaderLocked successfully")
            } catch (e: Throwable) {
                XposedBridge.log("TankeHook: Failed to hook LoadedApk: ${e.message}")
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
        // Native loading logic removed.
    }
}
