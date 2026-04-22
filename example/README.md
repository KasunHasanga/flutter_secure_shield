# SecureShield Example App

A demonstration of the `flutter_secure_shield` plugin features including device scanning, threat detection, and real-time security monitoring.

## 🚀 Getting Started

This example app showcases how to implement SecureShield in a real-world Flutter application.

### Prerequisites

- Flutter SDK (>=3.3.0)
- Android Studio / Xcode

### Running the demo

1.  Clone the repository:
    ```bash
    git clone https://github.com/KasunHasanga/flutter_secure_shield.git
    cd flutter_secure_shield/example
    ```

2.  Install dependencies:
    ```bash
    flutter pub get
    ```

3.  Run the application:
    ```bash
    flutter run
    ```

## 📸 What's Inside?

- **Real-time Scan**: Tap the floating action button to perform a full system security scan.
- **Threat Dashboard**: A visual representation of the device's overall security status and threat level.
- **Detailed Log**: A list of all performed checks and their specific results (Root, Emulator, Magisk, VPN, etc.).
- **Configuration Toggle**: Demonstrates how to configure the plugin to flag/ignore specific environments like emulators.

## 💡 Implementation Example

The core logic can be found in `lib/main.dart`:

```dart
// Run the scan
final result = await SecureShield.performFullScan();

// Check if device is safe
if (result.isSafe) {
  // Proceed with secure operations
} else {
  // Show warning or restrict access
}
```
