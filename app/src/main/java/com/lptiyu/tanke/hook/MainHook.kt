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

                        // 1. Ghost Instance Prevention: If mApplicationInfo is null, it's an Unsafe allocated object.
                        // We must immediately return to prevent NullPointerException and stack generation.
                        val appInfo = XposedHelpers.getObjectField(loadedApk, "mApplicationInfo") as? ApplicationInfo
                        if (appInfo == null) {
                            XposedBridge.log("TankeHook: Detected Ghost LoadedApk instance! Intercepting crash.")
                            param.result = null
                            return
                        }

                        // 2. AppComponentFactory Trap Prevention:
                        // The shell sets appComponentFactory to a nonexistent class (e.g. "com.lptiyu.tanke.lp")
                        // so that LoadedApk.createAppFactory() throws a ClassNotFoundException, which logs the hook stack trace.
                        // We temporarily clear it before original method executes so it uses the default factory safely.
                        val componentFactory = appInfo.appComponentFactory
                        if (componentFactory != null && (componentFactory == "com.lptiyu.tanke.lp" || componentFactory.contains("tanke"))) {
                            XposedBridge.log("TankeHook: Detected trap appComponentFactory: $componentFactory. Nullifying to prevent ClassNotFoundException.")
                            XposedHelpers.setObjectField(appInfo, "appComponentFactory", null)
                            // We attach the original factory name to the param to restore it later if needed
                            param.setObjectExtra("originalFactory", componentFactory)
                        }
                    }

                    @Throws(Throwable::class)
                    override fun afterHookedMethod(param: MethodHookParam) {
                        // Restore the appComponentFactory just in case the app checks it later
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

        try {
            System.loadLibrary("tanke-hook")
            XposedBridge.log("TankeHook: successfully loaded libtanke-hook.so")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: error loading library: ${e.message}")
            try {
                val appInfo = lpparam.appInfo
                val libDir = appInfo.nativeLibraryDir
                XposedBridge.log("TankeHook: appInfo nativeLibraryDir is $libDir")
            } catch (e2: Throwable) {
            }
        }
    }
}
