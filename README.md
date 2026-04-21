# 🛡 SecureShield

Advanced root detection and jailbreak detection Flutter plugin for Android and iOS.

## Features

### Android Root Detection
| Check | Description | Threat Level |
|-------|-------------|-------------|
| `suBinaries` | Scans 13+ known su binary locations | High |
| `suExists` | Checks if `su` is accessible via PATH | High |
| `rwPaths` | Detects writable system paths | High |
| `testKeys` | Build signed with test-keys | High |
| `dangerousProps` | Dangerous system properties (ro.debuggable etc.) | Medium |
| `busyboxInstalled` | BusyBox binary present | Medium |
| `magiskDetected` | Magisk + Magisk-Delta + KernelSU detection | Critical |
| `xposedDetected` | Xposed framework via stack trace + file scan | Critical |
| `hookingFramework` | Frida, Substrate, other hooking libs | Critical |
| `seLinuxBypass` | SELinux enforcing mode bypassed | High |
| `packageManager` | 18+ root/hack package names scanned | Medium |
| `buildTagsTest` | eng/userdebug build type detection | High |
| `adbEnabled` | ADB enabled via system settings | Medium |
| `developerOptions` | Developer options enabled | Low |
| `unknownSources` | Unknown sources installation enabled | Low |

### iOS Jailbreak Detection
| Check | Description | Threat Level |
|-------|-------------|-------------|
| `cydiaSources` | Cydia/Sileo/Zbra URL scheme check | Critical |
| `jailbrokenPaths` | 30+ jailbreak file/directory paths | Critical |
| `sandboxViolation` | Attempts to write outside sandbox | Critical |
| `substrateDylib` | MobileSubstrate/Substitute/libhooker dylibs | Critical |
| `openSSHInstalled` | OpenSSH daemon files present | High |
| `filePermissions` | Unexpected write permissions on system paths | High |
| `dyldEnvironment` | Suspicious DYLD_INSERT_LIBRARIES env vars | High |
| `syscallCheck` | fork() succeeds (jailbreak indicator) | High |
| `unsignedCode` | App running from non-standard location | High |
| `urlSchemes` | Suspicious jailbreak tool URL schemes | Medium |

### Cross-Platform
| Check | Description | Threat Level |
|-------|-------------|-------------|
| `emulatorDetected` | Emulator/simulator (configurable) | Low |
| `debuggerAttached` | Debugger/tracer attached (configurable) | Low |
| `vpnActive` | VPN connection detected | Low |
| `proxyDetected` | HTTP/HTTPS proxy configured | Medium |

## Installation

```yaml
dependencies:
  flutter_secure_shield:
    path: ./secure_shield  # or from pub.dev
```

## Usage

### Full Scan
```dart
import 'package:flutter_secure_shield/secure_shield.dart';

// Configure (optional)
await SecureShield.configure(
  failOnEmulator: false,
  failOnDebugger: false,
  customSuPaths: ['/data/custom/su'],
  customJailbreakPaths: ['/private/var/custom'],
);

// Run full scan
final result = await SecureShield.performFullScan();

if (!result.isSafe) {
  print('Threat level: ${result.overallThreatLevel.label}');
  print('Rooted: ${result.isRooted}');
  
  for (final threat in result.detectedThreats) {
    print('- ${threat.type.displayName}: ${threat.description}');
  }
}
```

### Quick Checks
```dart
final isRooted = await SecureShield.isRooted();
final isEmulator = await SecureShield.isEmulator();
final isDebugged = await SecureShield.isDebuggerAttached();

// Android-specific
final magisk = await SecureShield.isMagiskDetected();
final hooking = await SecureShield.isHookingFrameworkDetected();

// iOS-specific
final cydia = await SecureShield.isCydiaInstalled();

// Network
final vpn = await SecureShield.isVpnActive();
final proxy = await SecureShield.isProxyDetected();
```

### Selective Checks
```dart
final results = await SecureShield.runChecks([
  CheckType.magiskDetected,
  CheckType.xposedDetected,
  CheckType.debuggerAttached,
]);
```

### Blocking Compromised Devices
```dart
void initState() {
  super.initState();
  _checkSecurity();
}

Future<void> _checkSecurity() async {
  final result = await SecureShield.performFullScan();
  
  if (result.overallThreatLevel.isCompromised) {
    // Block access, show warning, or wipe local data
    Navigator.pushReplacementNamed(context, '/blocked');
  }
}
```

## Android Setup

Add to `AndroidManifest.xml`:
```xml
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
```

Minimum SDK: **21**

## iOS Setup

Add to `Info.plist` for URL scheme checks:
```xml
<key>LSApplicationQueriesSchemes</key>
<array>
  <string>cydia</string>
  <string>sileo</string>
  <string>zbra</string>
  <string>filza</string>
</array>
```

Minimum iOS: **13.0**

## Threat Levels

| Level | Value | Meaning |
|-------|-------|---------|
| `none` | SECURE | No threats detected |
| `low` | LOW RISK | Dev options, emulator, VPN |
| `medium` | MEDIUM RISK | Unknown sources, proxy, suspicious packages |
| `high` | HIGH RISK | Test keys, writable paths, OpenSSH |
| `critical` | CRITICAL | Active root/jailbreak, Magisk, Cydia, hooking |

Use `result.overallThreatLevel.isCompromised` to check if level is `high` or `critical`.

## Repository

[GitHub - KasunHasanga/flutter_secure_shield](https://github.com/KasunHasanga/flutter_secure_shield)

## License

MIT
