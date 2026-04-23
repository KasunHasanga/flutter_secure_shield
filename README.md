# 🛡️ SecureShield

Advanced root detection and jailbreak detection Flutter plugin with comprehensive security checks for Android and iOS.

[![pub package](https://img.shields.io/pub/v/flutter_secure_shield.svg)](https://pub.dev/packages/flutter_secure_shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SecureShield provides a robust set of security checks to help you protect your Flutter applications from compromised environments, unauthorized debugging, and malicious tools.

## ✨ Features

- 🔍 **Root & Jailbreak Detection**: Deep system checks for `su` binaries, Cydia, and other common indicators.
- 💻 **Emulator Detection**: Detects if the app is running on a virtual device or simulator.
- 🐛 **Debugger Protection**: Checks if a debugger is attached to the process.
- 🛠️ **Reverse Engineering Tools**: Detects Magisk, Xposed (Android), and Cydia (iOS).
- 🪝 **Hooking Frameworks**: Detects substrate and other hooking framework signatures.
- 🏗️ **Build Integrity**: Checks for test-keys, dangerous props, and sandbox violations.
- ⚙️ **System Settings**: Detects if ADB is enabled, Developer Options are active, or Unknown Sources are allowed (Android).
- 🌐 **Network Security**: Checks for active VPN connections and proxy configurations.
- 📊 **Threat Scoring**: Provides a comprehensive `ThreatLevel` (None, Low, Medium, High, Critical).
- ⚙️ **Configurable**: Define your own thresholds and custom paths to scan.

## 🚀 Installation

Add `flutter_secure_shield` to your `pubspec.yaml`:

```yaml
dependencies:
  flutter_secure_shield: ^1.0.2
```

Run `flutter pub get` to install.

## 🛠️ How It Works

SecureShield uses a combination of **Native Method Channels** and deep system calls to verify device integrity:

- **Android**: Scans for known root binaries, check build tags (test-keys), detects package managers like Magisk, and monitors for hooking framework signatures in the runtime.
- **iOS**: Checks for file system permissions in restricted areas, looks for common jailbreak apps (Cydia, Sileo, etc.), and tests for sandbox integrity via various system-level checks.
- **Unified API**: All native data is mapped into a consistent Dart model, making it easy to handle security logic in your app.

## 📖 Usage

### Initial Configuration (Optional)

You can configure the plugin early in your app's lifecycle:

```dart
import 'package:flutter_secure_shield/flutter_secure_shield.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await SecureShield.configure(
    failOnEmulator: false, // If true, emulators will be flagged as high threat
    failOnDebugger: true,   // Treat debuggers as high threat
    customSuPaths: ['/data/local/xbin/custom_su'],
  );
  
  runApp(MyApp());
}
```

### Performing a Full Security Scan

The recommended way to check device integrity:

```dart
final DetectionResult result = await SecureShield.performFullScan();

if (!result.isSafe) {
  print('Device is compromised!');
  print('Overall threat level: ${result.overallThreatLevel.label}');
  
  for (var threat in result.detectedThreats) {
    print('Detected: ${threat.type.displayName} - ${threat.description}');
  }
} else {
  print('Device is secure!');
}
```

### Individual Security Checks

You can also run specific checks if you don't need a full report:

```dart
bool isRooted = await SecureShield.isRooted();
bool isEmulator = await SecureShield.isEmulator();
bool isVpnActive = await SecureShield.isVpnActive();
bool IsDebuggerAttached = await SecureShield.isDebuggerAttached();
```

### Selective Checks

Run only the checks you care about to save performance:

```dart
final List<CheckResult> results = await SecureShield.runChecks([
  CheckType.isRooted,
  CheckType.isVpnActive,
  CheckType.isDebuggerAttached,
]);
```

## 📊 Threat Levels

| Level | Description | Recommended Action |
| :--- | :--- | :--- |
| **None** | No threats detected. | Proceed normally. |
| **Low** | Minor issues (e.g., Debugger attached in dev). | Log or warn user. |
| **Medium** | Indicators of potential risk (e.g., VPN/Proxy). | Monitor or request user action. |
| **High** | Device is likely compromised or running in emulator. | Restrict sensitive features. |
| **Critical** | Confirmed Root/Jailbreak or Hooking framework. | Terminate app or block access. |

## 🛡️ Best Practices

1. **Scan on Startup**: Perform a scan before allowing access to sensitive data.
2. **Scan Before Transactions**: Verify device integrity before processing payments or sensitive operations.
3. **Don't Just Exit**: Instead of just crashing, show a user-friendly message explaining why the app won't run.
4. **Use `ThreatLevel`**: Base your app logic on the `overallThreatLevel` rather than individual trues/falses for better flexibility.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
