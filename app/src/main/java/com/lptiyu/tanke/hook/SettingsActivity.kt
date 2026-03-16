package com.lptiyu.tanke.hook

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView

/**
 * LSPosed 模块设置界面。
 * 纯代码构建 UI，无需 XML/AppCompat，最小化依赖。
 *
 * 开关值保存在 MODE_WORLD_READABLE SharedPreferences；
 * MainHook 在每次 handleLoadPackage 时通过 XSharedPreferences 读取。
 */
class SettingsActivity : Activity() {

    companion object {
        const val PREFS_NAME = "tanke_hook_prefs"

        // SharedPreferences key 常量，与 MainHook 共享
        const val KEY_BYPASS_SSL         = "bypass_ssl_pinning"
        const val KEY_DISABLE_HTTPDNS    = "disable_httpdns"
        const val KEY_DISABLE_ADS        = "disable_ads"
        const val KEY_SKIP_SPLASH_AD     = "skip_splash_ad"
        const val KEY_ANTI_DETECT        = "anti_detect"
        const val KEY_VERBOSE_LOG        = "verbose_log"
    }

    private data class PrefEntry(
        val key: String,
        val title: String,
        val summary: String,
        val defaultValue: Boolean
    )

    private val entries = listOf(
        PrefEntry(KEY_ANTI_DETECT,     "反检测（栈帧伪装）",
            "伪造调用栈帧，绕过应用的 Xposed 框架检测", true),
        PrefEntry(KEY_BYPASS_SSL,      "绕过 SSL Pinning",
            "禁用证书校验与 HostnameVerifier，用于抓包分析", true),
        PrefEntry(KEY_DISABLE_HTTPDNS, "禁用阿里云 HttpDNS",
            "阻止 OSS SDK 使用 IP 直连，使抓包代理可以正常捕获上传流量", true),
        PrefEntry(KEY_DISABLE_ADS,     "去广告（拦截 SDK 初始化）",
            "阻止 YFAds / 北智融合 / 快手 KsAd 等 SDK 完成初始化", true),
        PrefEntry(KEY_SKIP_SPLASH_AD,  "跳过启动广告",
            "拦截 SplashActivity 中的开屏广告展示，直接进入主界面", true),
        PrefEntry(KEY_VERBOSE_LOG,     "详细日志",
            "在 logcat 中输出每个 Hook 命中记录（调试用）", false)
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_WORLD_READABLE)

        val root = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#F2F2F7"))
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(16), 0, dp(32))
        }

        // 标题卡片
        container.addView(buildSectionHeader("Tanke LSPosed Hook"))
        container.addView(buildCaption("设置将在下次目标应用启动时生效"))

        // 功能开关列表
        container.addView(buildSectionLabel("功能开关"))
        val card = buildCard()
        entries.forEachIndexed { index, entry ->
            val current = prefs.getBoolean(entry.key, entry.defaultValue)
            card.addView(buildSwitchRow(entry, current, prefs, index < entries.size - 1))
        }
        container.addView(card)

        // 说明
        container.addView(buildCaption("部分功能需要 LSPosed 框架版本 ≥ 1.9.2，且模块已激活作用域为 com.lptiyu.tanke。"))

        root.addView(container)
        setContentView(root)
        title = "Tanke Hook 设置"
    }

    @Suppress("DEPRECATION")
    private fun buildSwitchRow(
        entry: PrefEntry,
        initialValue: Boolean,
        prefs: android.content.SharedPreferences,
        showDivider: Boolean
    ): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(16), dp(14), dp(12), dp(14))
            gravity = Gravity.CENTER_VERTICAL
        }

        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val titleView = TextView(this).apply {
            text = entry.title
            textSize = 16f
            setTextColor(Color.parseColor("#1C1C1E"))
            setTypeface(typeface, Typeface.NORMAL)
        }
        val summaryView = TextView(this).apply {
            text = entry.summary
            textSize = 13f
            setTextColor(Color.parseColor("#8E8E93"))
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
        }
        texts.addView(titleView)
        texts.addView(summaryView)

        val toggle = Switch(this).apply {
            isChecked = initialValue
            setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean(entry.key, isChecked).apply()
            }
        }

        row.addView(texts)
        row.addView(toggle)

        if (!showDivider) return row

        val wrapper = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        wrapper.addView(row)
        wrapper.addView(View(this).apply {
            setBackgroundColor(Color.parseColor("#C6C6C8"))
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1
            ).apply { marginStart = dp(16) }
            layoutParams = lp
        })
        return wrapper
    }

    private fun buildCard(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(dp(16), 0, dp(16), dp(8))
            }
            layoutParams = lp
            // 圆角阴影通过 elevation 实现（API 21+）
            elevation = dp(2).toFloat()
        }
    }

    private fun buildSectionHeader(text: String): View {
        return TextView(this).apply {
            this.text = text
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
            setTextColor(Color.parseColor("#1C1C1E"))
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(20), dp(8), dp(20), dp(4)) }
            layoutParams = lp
        }
    }

    private fun buildSectionLabel(text: String): View {
        return TextView(this).apply {
            this.text = text.uppercase()
            textSize = 12f
            setTextColor(Color.parseColor("#6D6D72"))
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(32), dp(20), dp(32), dp(6)) }
            layoutParams = lp
        }
    }

    private fun buildCaption(text: String): View {
        return TextView(this).apply {
            this.text = text
            textSize = 12f
            setTextColor(Color.parseColor("#8E8E93"))
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(dp(32), dp(4), dp(32), dp(4)) }
            layoutParams = lp
        }
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density + 0.5f).toInt()
    }
}
