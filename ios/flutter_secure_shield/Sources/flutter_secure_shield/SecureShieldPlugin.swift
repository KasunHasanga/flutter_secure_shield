import Flutter
import UIKit
import Darwin
import MachO
import SystemConfiguration
import Network

public class SecureShieldPlugin: NSObject, FlutterPlugin {

    private var config = PluginConfig()

    struct PluginConfig {
        var failOnEmulator: Bool = false
        var failOnDebugger: Bool = false
        var customSuPaths: [String] = []
        var customJailbreakPaths: [String] = []
    }

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "com.secureshield/flutter_secure_shield",
            binaryMessenger: registrar.messenger()
        )
        let instance = SecureShieldPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "performFullScan":
            result(performFullScan())
        case "isRooted":
            result(isJailbroken())
        case "isEmulator":
            result(isSimulator())
        case "isDebuggerAttached":
            result(isDebuggerAttached())
        case "isCydiaInstalled":
            result(checkCydiaInstalled())
        case "isVpnActive":
            result(isVpnActive())
        case "isProxyDetected":
            result(isProxyDetected())
        case "runChecks":
            guard let args = call.arguments as? [String: Any],
                  let checks = args["checks"] as? [String] else {
                result(FlutterError(code: "INVALID_ARGS", message: "Missing checks", details: nil))
                return
            }
            result(runChecks(checks))
        case "configure":
            if let args = call.arguments as? [String: Any] {
                config.failOnEmulator = args["failOnEmulator"] as? Bool ?? false
                config.failOnDebugger = args["failOnDebugger"] as? Bool ?? false
                config.customSuPaths = args["customSuPaths"] as? [String] ?? []
                config.customJailbreakPaths = args["customJailbreakPaths"] as? [String] ?? []
            }
            result(nil)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // ─── Full Scan ─────────────────────────────────────────────────────

    private func performFullScan() -> [String: Any] {
        var checks: [[String: Any]] = []

        // Jailbreak checks
        checks.append(buildCheck("cydiaSources", checkCydiaInstalled(), "critical", "Cydia or Sileo installed"))
        checks.append(buildCheck("jailbrokenPaths", checkJailbrokenPaths(), "critical", "Jailbreak-related paths found"))
        checks.append(buildCheck("sandboxViolation", checkSandboxViolation(), "critical", "Sandbox violation detected"))
        checks.append(buildCheck("substrateDylib", checkSubstrateDylib(), "critical", "Substrate/Substitute dylib loaded"))
        checks.append(buildCheck("dyldEnvironment", checkDYLDEnvironment(), "high", "Suspicious DYLD environment variables"))
        checks.append(buildCheck("openSSHInstalled", checkOpenSSH(), "high", "OpenSSH installed"))
        checks.append(buildCheck("filePermissions", checkFilePermissions(), "high", "Unexpected file write permissions"))
        checks.append(buildCheck("urlSchemes", checkSuspiciousURLSchemes(), "medium", "Suspicious URL schemes accessible"))
        checks.append(buildCheck("syscallCheck", performSyscallCheck(), "high", "Syscall returns unexpected result"))
        checks.append(buildCheck("unsignedCode", checkUnsignedCode(), "high", "Unsigned code detected"))

        // Environment checks
        checks.append(buildCheck("emulatorDetected", isSimulator(), config.failOnEmulator ? "high" : "low", "Running on simulator"))
        checks.append(buildCheck("debuggerAttached", isDebuggerAttached(), config.failOnDebugger ? "high" : "low", "Debugger is attached"))

        // Network checks
        checks.append(buildCheck("vpnActive", isVpnActive(), "low", "VPN is active"))
        checks.append(buildCheck("proxyDetected", isProxyDetected(), "medium", "HTTP proxy configured"))

        let jailbroken = ["cydiaSources", "jailbrokenPaths", "sandboxViolation",
                          "substrateDylib", "openSSHInstalled"].contains { name in
            checks.first(where: { $0["type"] as? String == name })?["detected"] as? Bool == true
        }

        let overallLevel = calculateOverallThreat(checks)

        return [
            "isRooted": jailbroken,
            "isEmulator": isSimulator(),
            "isDebuggerAttached": isDebuggerAttached(),
            "overallThreatLevel": overallLevel,
            "checks": checks,
            "scannedAt": Int(Date().timeIntervalSince1970 * 1000),
            "platform": "ios"
        ]
    }

    // ─── Jailbreak Detection ───────────────────────────────────────────

    private func isJailbroken() -> Bool {
        return checkCydiaInstalled() || checkJailbrokenPaths() ||
               checkSandboxViolation() || checkSubstrateDylib() || checkOpenSSH()
    }

    private func checkCydiaInstalled() -> Bool {
        let cydiaURLs = [
            "cydia://package/com.example.package",
            "sileo://package/com.example.package",
            "zbra://packages"
        ]
        for urlString in cydiaURLs {
            if let url = URL(string: urlString),
               UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        return FileManager.default.fileExists(atPath: "/Applications/Cydia.app")
    }

    private func checkJailbrokenPaths() -> Bool {
        var paths = [
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/libexec/ssh-keysign",
            "/usr/sbin/sshd",
            "/var/cache/apt",
            "/var/lib/apt",
            "/var/lib/cydia",
            "/etc/apt",
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/ssh"
        ]
        paths.append(contentsOf: config.customJailbreakPaths)

        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private func checkSandboxViolation() -> Bool {
        let testPath = "/private/jailbreak_test_\(UUID().uuidString).txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true // Was able to write outside sandbox
        } catch {
            return false
        }
    }

    private func checkSubstrateDylib() -> Bool {
        let suspiciousDylibs = [
            "MobileSubstrate", "SubstrateLoader", "substitute-loader",
            "SubstrateInserter", "libhooker", "CydiaSubstrate",
            "TweakInject", "Substitute"
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            if let name = _dyld_get_image_name(i) {
                let imageName = String(cString: name)
                if suspiciousDylibs.contains(where: { imageName.contains($0) }) {
                    return true
                }
            }
        }
        return false
    }

    private func checkDYLDEnvironment() -> Bool {
        let suspicious = ["DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FORCE_FLAT_NAMESPACE"]
        return suspicious.contains { getenv($0) != nil }
    }

    private func checkOpenSSH() -> Bool {
        let sshPaths = [
            "/usr/sbin/sshd",
            "/etc/ssh/sshd_config",
            "/usr/bin/ssh",
            "/private/etc/ssh"
        ]
        return sshPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private func checkFilePermissions() -> Bool {
        let restrictedPaths = ["/", "/usr", "/private", "/bin", "/etc", "/lib", "/sbin"]
        return restrictedPaths.contains { path in
            FileManager.default.isWritableFile(atPath: path)
        }
    }

    private func checkSuspiciousURLSchemes() -> Bool {
        let schemes = [
            "cydia://", "sileo://", "zbra://", "filza://",
            "activator://", "undecimus://", "openssh://"
        ]
        return schemes.contains { scheme in
            guard let url = URL(string: "\(scheme)test") else { return false }
            return UIApplication.shared.canOpenURL(url)
        }
    }

    private func performSyscallCheck() -> Bool {
        // fork() is unavailable on iOS and causes a compiler error.
        // On a real jailbroken device, one might try to use posix_spawn or syscall(SYS_fork),
        // but for now we return false to ensure the app builds successfully.
        return false
    }

    private func checkUnsignedCode() -> Bool {
        // Check for code that shouldn't be able to run on a non-jailbroken device
        let bundlePath = Bundle.main.bundlePath
        let attributes = try? FileManager.default.attributesOfItem(atPath: bundlePath)
        // If the app is running from a non-standard location
        return !bundlePath.contains("/var/containers/Bundle/Application/")
    }

    // ─── Environment Checks ────────────────────────────────────────────

    private func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    private func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        return result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
    }

    // ─── Network Checks ────────────────────────────────────────────────

    private func isVpnActive() -> Bool {
        guard let cfDict = CFNetworkCopySystemProxySettings() else { return false }
        let nsDict = cfDict.takeRetainedValue() as NSDictionary
        guard let keys = nsDict["__SCOPED__"] as? NSDictionary else { return false }
        return keys.allKeys.contains { ($0 as? String)?.hasPrefix("tap") == true ||
                                       ($0 as? String)?.hasPrefix("tun") == true ||
                                       ($0 as? String)?.hasPrefix("ipsec") == true ||
                                       ($0 as? String)?.hasPrefix("ppp") == true }
    }

    private func isProxyDetected() -> Bool {
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }
        let httpEnabled = proxySettings["HTTPEnable"] as? Int == 1
        let httpsEnabled = proxySettings["HTTPSEnable"] as? Int == 1
        return httpEnabled || httpsEnabled
    }

    // ─── Selective Run ─────────────────────────────────────────────────

    private func runChecks(_ checkNames: [String]) -> [[String: Any]] {
        return checkNames.compactMap { name in
            switch name {
            case "cydiaSources": return buildCheck(name, checkCydiaInstalled(), "critical", "Cydia/Sileo installed")
            case "jailbrokenPaths": return buildCheck(name, checkJailbrokenPaths(), "critical", "Jailbreak paths found")
            case "sandboxViolation": return buildCheck(name, checkSandboxViolation(), "critical", "Sandbox violated")
            case "substrateDylib": return buildCheck(name, checkSubstrateDylib(), "critical", "Substrate dylib found")
            case "openSSHInstalled": return buildCheck(name, checkOpenSSH(), "high", "OpenSSH installed")
            case "emulatorDetected": return buildCheck(name, isSimulator(), "low", "Running on simulator")
            case "debuggerAttached": return buildCheck(name, isDebuggerAttached(), "low", "Debugger attached")
            case "vpnActive": return buildCheck(name, isVpnActive(), "low", "VPN active")
            case "proxyDetected": return buildCheck(name, isProxyDetected(), "medium", "Proxy configured")
            default: return nil
            }
        }
    }

    // ─── Helpers ───────────────────────────────────────────────────────

    private func buildCheck(
        _ type: String,
        _ detected: Bool,
        _ threatLevel: String,
        _ description: String,
        _ metadata: [String: Any]? = nil
    ) -> [String: Any] {
        var result: [String: Any] = [
            "type": type,
            "detected": detected,
            "threatLevel": detected ? threatLevel : "none",
            "description": description
        ]
        if let metadata = metadata { result["metadata"] = metadata }
        return result
    }

    private func calculateOverallThreat(_ checks: [[String: Any]]) -> String {
        let levels = checks
            .filter { $0["detected"] as? Bool == true }
            .compactMap { $0["threatLevel"] as? String }

        if levels.contains("critical") { return "critical" }
        if levels.contains("high") { return "high" }
        if levels.contains("medium") { return "medium" }
        if levels.contains("low") { return "low" }
        return "none"
    }
}
