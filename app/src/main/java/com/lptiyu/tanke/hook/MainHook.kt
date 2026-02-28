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
            System.loadLibrary("tanke-hook")
            XposedBridge.log("TankeHook: successfully loaded libtanke-hook.so")
        } catch (e: Throwable) {
            XposedBridge.log("TankeHook: error loading library: ${e.message}")
        }
    }
}
