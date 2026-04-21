package com.secureshield.flutter_secure_shield

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class SecureShieldPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private var config = PluginConfig()

    data class PluginConfig(
        val failOnEmulator: Boolean = false,
        val failOnDebugger: Boolean = false,
        val customSuPaths: List<String> = emptyList(),
        val customJailbreakPaths: List<String> = emptyList()
    )

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "com.secureshield/flutter_secure_shield")
        channel.setMethodCallHandler(this)
        context = binding.applicationContext
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "performFullScan" -> result.success(performFullScan())
            "isRooted" -> result.success(isRooted())
            "isEmulator" -> result.success(isEmulator())
            "isDebuggerAttached" -> result.success(isDebuggerAttached())
            "isMagiskDetected" -> result.success(isMagiskDetected())
            "isHookingFrameworkDetected" -> result.success(isHookingFrameworkDetected())
            "isVpnActive" -> result.success(isVpnActive())
            "isProxyDetected" -> result.success(isProxyDetected())
            "runChecks" -> {
                val checks = call.argument<List<String>>("checks") ?: emptyList()
                result.success(runChecks(checks))
            }
            "configure" -> {
                config = PluginConfig(
                    failOnEmulator = call.argument<Boolean>("failOnEmulator") ?: false,
                    failOnDebugger = call.argument<Boolean>("failOnDebugger") ?: false,
                    customSuPaths = call.argument<List<String>>("customSuPaths") ?: emptyList(),
                    customJailbreakPaths = call.argument<List<String>>("customJailbreakPaths") ?: emptyList()
                )
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    // ─── Full Scan ─────────────────────────────────────────────────────

    private fun performFullScan(): Map<String, Any> {
        val checks = mutableListOf<Map<String, Any>>()

        // Root checks
        checks.add(buildCheck("suBinaries", checkSuBinaries(), "high", "SU binaries found in common locations"))
        checks.add(buildCheck("suExists", checkSuExists(), "high", "SU binary accessible via PATH"))
        checks.add(buildCheck("rwPaths", checkRWPaths(), "high", "System paths are writable"))
        checks.add(buildCheck("testKeys", checkTestKeys(), "high", "Device built with test-keys"))
        checks.add(buildCheck("dangerousProps", checkDangerousProps(), "medium", "Dangerous system properties detected"))
        checks.add(buildCheck("busyboxInstalled", checkBusybox(), "medium", "BusyBox binary found"))
        checks.add(buildCheck("magiskDetected", isMagiskDetected(), "critical", "Magisk root management detected"))
        checks.add(buildCheck("xposedDetected", checkXposed(), "critical", "Xposed Framework detected"))
        checks.add(buildCheck("hookingFramework", isHookingFrameworkDetected(), "critical", "Runtime hooking framework detected"))
        checks.add(buildCheck("seLinuxBypass", checkSELinuxBypass(), "high", "SELinux appears to be bypassed"))
        checks.add(buildCheck("packageManager", checkSuspiciousPackages(), "medium", "Root-related packages found"))
        checks.add(buildCheck("buildTagsTest", checkBuildTags(), "high", "Build tags indicate non-production build"))

        // Environment checks
        checks.add(buildCheck("emulatorDetected", isEmulator(), if (config.failOnEmulator) "high" else "low", "Running inside an emulator"))
        checks.add(buildCheck("debuggerAttached", isDebuggerAttached(), if (config.failOnDebugger) "high" else "low", "Debugger is attached to process"))
        checks.add(buildCheck("adbEnabled", checkAdbEnabled(), "medium", "ADB is enabled"))
        checks.add(buildCheck("developerOptions", checkDeveloperOptions(), "low", "Developer options are enabled"))
        checks.add(buildCheck("unknownSources", checkUnknownSources(), "low", "Installation from unknown sources is enabled"))

        // Network checks
        checks.add(buildCheck("vpnActive", isVpnActive(), "low", "VPN connection is active"))
        checks.add(buildCheck("proxyDetected", isProxyDetected(), "medium", "HTTP proxy is configured"))

        val rootDetected = checks.any { check ->
            check["detected"] == true && check["type"] in listOf(
                "suBinaries", "suExists", "rwPaths", "testKeys", "magiskDetected",
                "xposedDetected", "hookingFramework", "busyboxInstalled"
            )
        }

        val overallLevel = calculateOverallThreat(checks)

        return mapOf(
            "isRooted" to rootDetected,
            "isEmulator" to isEmulator(),
            "isDebuggerAttached" to isDebuggerAttached(),
            "overallThreatLevel" to overallLevel,
            "checks" to checks,
            "scannedAt" to System.currentTimeMillis(),
            "platform" to "android"
        )
    }

    // ─── Root Detection Checks ─────────────────────────────────────────

    private fun checkSuBinaries(): Boolean {
        val suPaths = mutableListOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
            "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu", "/data/local/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/dev/com.koushikdutta.superuser.daemon/"
        )
        suPaths.addAll(config.customSuPaths)
        return suPaths.any { File(it).exists() }
    }

    private fun checkSuExists(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val line = reader.readLine()
            process.destroy()
            !line.isNullOrBlank()
        } catch (e: Exception) { false }
    }

    private fun checkRWPaths(): Boolean {
        val paths = listOf("/system", "/system/bin", "/system/sbin",
            "/system/xbin", "/vendor/bin", "/sbin", "/etc")
        return paths.any { path ->
            try {
                val file = File(path)
                file.exists() && file.canWrite()
            } catch (e: Exception) { false }
        }
    }

    private fun checkTestKeys(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkBuildTags(): Boolean {
        return Build.TYPE in listOf("eng", "userdebug") ||
                (Build.TAGS != null && Build.TAGS.contains("test-keys"))
    }

    private fun checkDangerousProps(): Boolean {
        val dangerousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "ro.allow.mock.location" to "1",
            "ro.monkey" to "1"
        )
        return dangerousProps.any { (key, value) ->
            try {
                val process = Runtime.getRuntime().exec("getprop $key")
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val result = reader.readLine()?.trim()
                process.destroy()
                result == value
            } catch (e: Exception) { false }
        }
    }

    private fun checkBusybox(): Boolean {
        val paths = listOf("/system/xbin/busybox", "/system/bin/busybox",
            "/sbin/busybox", "/data/local/busybox")
        return paths.any { File(it).exists() }
    }

    fun isMagiskDetected(): Boolean {
        val magiskPaths = listOf(
            "/sbin/.magisk", "/sbin/.core/mirror", "/sbin/.core/img",
            "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu",
            "/cache/.disable_magisk", "/dev/magisk_merge", "/sbin/.core/img"
        )
        val magiskPackages = listOf(
            "com.topjohnwu.magisk", "com.fox2code.mmm", "io.github.huskydg.magisk"
        )
        val pathDetected = magiskPaths.any { File(it).exists() }
        val pkgDetected = magiskPackages.any { pkg ->
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) { false }
        }
        return pathDetected || pkgDetected
    }

    private fun checkXposed(): Boolean {
        return try {
            throw Exception("XposedCheck")
        } catch (e: Exception) {
            e.stackTrace.any { it.className.contains("de.robv.android.xposed") }
        }.let { stackDetected ->
            val xposedFiles = listOf(
                "/system/framework/XposedBridge.jar",
                "/data/data/de.robv.android.xposed.installer",
                "/system/xposed.prop"
            )
            stackDetected || xposedFiles.any { File(it).exists() }
        }
    }

    fun isHookingFrameworkDetected(): Boolean {
        val hookingLibs = listOf(
            "libsubstrate.so", "libcydiasubstrate.so", "libfrida-agent.so",
            "libfrida-gadget.so", "libreframeworkd.so", "libssl_bypass.so",
            "xlua.jar", "EdXposed.apk"
        )
        return hookingLibs.any { lib ->
            try {
                System.loadLibrary(lib.removeSuffix(".so").removeSuffix(".jar"))
                true
            } catch (e: UnsatisfiedLinkError) {
                File("/system/lib/$lib").exists() || File("/system/lib64/$lib").exists()
            }
        }
    }

    private fun checkSELinuxBypass(): Boolean {
        return try {
            val file = File("/sys/fs/selinux/enforce")
            if (!file.exists()) return false
            val content = file.readText().trim()
            content == "0"
        } catch (e: Exception) { false }
    }

    private fun checkSuspiciousPackages(): Boolean {
        val rootPackages = listOf(
            "com.noshufou.android.su", "com.noshufou.android.su.elite",
            "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.thirdparty.superuser", "com.yellowes.su",
            "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
            "com.formyhm.hideroot", "com.formyhm.hiderootpremium",
            "me.phh.superuser", "com.kingouser.com", "com.android.vending.billing.InAppBillingService.LACK"
        )
        return rootPackages.any { pkg ->
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) { false }
        }
    }

    // ─── Environment Checks ────────────────────────────────────────────

    fun isEmulator(): Boolean {
        val buildFingerprint = Build.FINGERPRINT.lowercase()
        val buildModel = Build.MODEL.lowercase()
        val buildManufacturer = Build.MANUFACTURER.lowercase()
        val buildBrand = Build.BRAND.lowercase()
        val buildDevice = Build.DEVICE.lowercase()
        val buildProduct = Build.PRODUCT.lowercase()
        val buildHardware = Build.HARDWARE.lowercase()

        val emulatorIndicators = listOf(
            buildFingerprint.contains("generic"),
            buildFingerprint.contains("unknown"),
            buildModel.contains("google_sdk"),
            buildModel.contains("emulator"),
            buildModel.contains("android sdk built for x86"),
            buildManufacturer.contains("genymotion"),
            buildBrand.startsWith("generic"),
            buildDevice.contains("generic"),
            buildProduct.contains("sdk_gphone"),
            buildProduct.contains("google_sdk"),
            buildProduct.contains("sdk"),
            buildProduct.contains("sdk_x86"),
            buildProduct.contains("vbox86p"),
            buildHardware.contains("goldfish"),
            buildHardware.contains("ranchu"),
            buildHardware.contains("vbox86"),
            Build.BOARD.lowercase().contains("nox"),
            Build.HOST.lowercase().contains("nox"),
            Build.SERIAL?.lowercase()?.contains("unknown") == true
        )

        return emulatorIndicators.count { it } >= 2
    }

    fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    private fun checkAdbEnabled(): Boolean {
        return try {
            val adbEnabled = android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.ADB_ENABLED,
                0
            )
            adbEnabled == 1
        } catch (e: Exception) { false }
    }

    private fun checkDeveloperOptions(): Boolean {
        return try {
            val devOptions = android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            )
            devOptions == 1
        } catch (e: Exception) { false }
    }

    @Suppress("DEPRECATION")
    private fun checkUnknownSources(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.packageManager.canRequestPackageInstalls()
            } else {
                android.provider.Settings.Secure.getInt(
                    context.contentResolver,
                    android.provider.Settings.Secure.INSTALL_NON_MARKET_APPS,
                    0
                ) == 1
            }
        } catch (e: Exception) { false }
    }

    // ─── Network Checks ────────────────────────────────────────────────

    fun isVpnActive(): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val network = cm.activeNetwork ?: return false
                val caps = cm.getNetworkCapabilities(network) ?: return false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } else {
                @Suppress("DEPRECATION")
                cm.getNetworkInfo(ConnectivityManager.TYPE_VPN)?.isConnected == true
            }
        } catch (e: Exception) { false }
    }

    fun isProxyDetected(): Boolean {
        val host = System.getProperty("http.proxyHost")
        val port = System.getProperty("http.proxyPort")
        return !host.isNullOrBlank() && !port.isNullOrBlank()
    }

    // ─── Selective Run ─────────────────────────────────────────────────

    private fun runChecks(checkNames: List<String>): List<Map<String, Any>> {
        return checkNames.mapNotNull { name ->
            when (name) {
                "suBinaries" -> buildCheck(name, checkSuBinaries(), "high", "SU binaries found")
                "suExists" -> buildCheck(name, checkSuExists(), "high", "SU binary in PATH")
                "rwPaths" -> buildCheck(name, checkRWPaths(), "high", "Writable system paths")
                "testKeys" -> buildCheck(name, checkTestKeys(), "high", "Test-keys build")
                "dangerousProps" -> buildCheck(name, checkDangerousProps(), "medium", "Dangerous props")
                "busyboxInstalled" -> buildCheck(name, checkBusybox(), "medium", "BusyBox found")
                "magiskDetected" -> buildCheck(name, isMagiskDetected(), "critical", "Magisk detected")
                "xposedDetected" -> buildCheck(name, checkXposed(), "critical", "Xposed detected")
                "hookingFramework" -> buildCheck(name, isHookingFrameworkDetected(), "critical", "Hooking framework")
                "emulatorDetected" -> buildCheck(name, isEmulator(), "low", "Emulator detected")
                "debuggerAttached" -> buildCheck(name, isDebuggerAttached(), "low", "Debugger attached")
                "adbEnabled" -> buildCheck(name, checkAdbEnabled(), "medium", "ADB enabled")
                "vpnActive" -> buildCheck(name, isVpnActive(), "low", "VPN active")
                "proxyDetected" -> buildCheck(name, isProxyDetected(), "medium", "Proxy detected")
                else -> null
            }
        }
    }

    // ─── Helpers ───────────────────────────────────────────────────────

    private fun buildCheck(
        type: String,
        detected: Boolean,
        threatLevel: String,
        description: String,
        metadata: Map<String, Any>? = null
    ): Map<String, Any> {
        val effectiveThreatLevel = if (detected) threatLevel else "none"
        return buildMap {
            put("type", type)
            put("detected", detected)
            put("threatLevel", effectiveThreatLevel)
            put("description", description)
            if (metadata != null) put("metadata", metadata)
        }
    }

    private fun calculateOverallThreat(checks: List<Map<String, Any>>): String {
        val levels = checks
            .filter { it["detected"] == true }
            .map { it["threatLevel"] as String }

        return when {
            "critical" in levels -> "critical"
            "high" in levels -> "high"
            "medium" in levels -> "medium"
            "low" in levels -> "low"
            else -> "none"
        }
    }

    fun isRooted(): Boolean {
        return checkSuBinaries() || checkSuExists() || checkRWPaths() ||
                checkTestKeys() || isMagiskDetected() || isHookingFrameworkDetected() ||
                checkBusybox()
    }
}
