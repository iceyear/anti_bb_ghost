package com.lptiyu.tanke.hook

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

class MainHook : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        if (lpparam.packageName != "com.lptiyu.tanke") {
            return
        }
        XposedBridge.log("TankeHook: loading for ${lpparam.packageName}")
        try {
            // When running in an LSPosed module context, System.loadLibrary might not find the
            // module's own library easily because it looks in the target app's lib directory.
            // A more robust approach is to load the module's path if needed, but LSPosed
            // sets up the classloader correctly if extracted properly.
            System.loadLibrary("tanke-hook")
            XposedBridge.log("TankeHook: successfully loaded libtanke-hook.so")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: error loading library: ${e.message}")
            // Fallback for Xposed environments where System.loadLibrary fails
            try {
                val appInfo = lpparam.appInfo
                val libDir = appInfo.nativeLibraryDir
                XposedBridge.log("TankeHook: appInfo nativeLibraryDir is $libDir")
            } catch (e2: Throwable) {
            }
        }
    }
}
