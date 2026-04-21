import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'models/detection_result.dart';
import 'models/check_type.dart';

/// SecureShield — Advanced root and jailbreak detection plugin.
///
/// Usage:
/// ```dart
/// final result = await SecureShield.performFullScan();
/// if (!result.isSafe) {
///   // Handle compromised device
/// }
/// ```
class SecureShield {
  static const MethodChannel _channel =
      MethodChannel('com.secureshield/flutter_secure_shield');

  // ─── Full Scan ───────────────────────────────────────────────────

  /// Performs a comprehensive security scan and returns [DetectionResult].
  static Future<DetectionResult> performFullScan() async {
    try {
      final Map<dynamic, dynamic> result =
          await _channel.invokeMethod('performFullScan');
      return DetectionResult.fromMap(Map<String, dynamic>.from(result));
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] Error during full scan: ${e.message}');
      rethrow;
    }
  }

  // ─── Individual Checks ───────────────────────────────────────────

  /// Returns true if the device is rooted (Android) or jailbroken (iOS).
  static Future<bool> isRooted() async {
    try {
      return await _channel.invokeMethod<bool>('isRooted') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isRooted error: ${e.message}');
      return false;
    }
  }

  /// Returns true if running inside an emulator or simulator.
  static Future<bool> isEmulator() async {
    try {
      return await _channel.invokeMethod<bool>('isEmulator') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isEmulator error: ${e.message}');
      return false;
    }
  }

  /// Returns true if a debugger is currently attached.
  static Future<bool> isDebuggerAttached() async {
    try {
      return await _channel.invokeMethod<bool>('isDebuggerAttached') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isDebuggerAttached error: ${e.message}');
      return false;
    }
  }

  /// [Android only] Returns true if Magisk is detected.
  static Future<bool> isMagiskDetected() async {
    if (!defaultTargetPlatform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('isMagiskDetected') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isMagiskDetected error: ${e.message}');
      return false;
    }
  }

  /// [Android only] Returns true if Xposed or similar hooking framework detected.
  static Future<bool> isHookingFrameworkDetected() async {
    if (!defaultTargetPlatform.isAndroid) return false;
    try {
      return await _channel
              .invokeMethod<bool>('isHookingFrameworkDetected') ??
          false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isHookingFrameworkDetected error: ${e.message}');
      return false;
    }
  }

  /// [iOS only] Returns true if Cydia or similar is installed.
  static Future<bool> isCydiaInstalled() async {
    if (!defaultTargetPlatform.isIOS) return false;
    try {
      return await _channel.invokeMethod<bool>('isCydiaInstalled') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isCydiaInstalled error: ${e.message}');
      return false;
    }
  }

  /// Returns true if a VPN connection is active.
  static Future<bool> isVpnActive() async {
    try {
      return await _channel.invokeMethod<bool>('isVpnActive') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isVpnActive error: ${e.message}');
      return false;
    }
  }

  /// Returns true if a proxy is configured on the device.
  static Future<bool> isProxyDetected() async {
    try {
      return await _channel.invokeMethod<bool>('isProxyDetected') ?? false;
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] isProxyDetected error: ${e.message}');
      return false;
    }
  }

  // ─── Selective Scan ──────────────────────────────────────────────

  /// Runs only a specified set of checks.
  static Future<List<CheckResult>> runChecks(List<CheckType> checks) async {
    try {
      final List<dynamic> result = await _channel.invokeMethod(
        'runChecks',
        {'checks': checks.map((c) => c.name).toList()},
      );
      return result
          .map((r) => CheckResult.fromMap(Map<String, dynamic>.from(r as Map)))
          .toList();
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] runChecks error: ${e.message}');
      rethrow;
    }
  }

  // ─── Configuration ───────────────────────────────────────────────

  /// Configures the plugin behavior.
  ///
  /// [failOnEmulator] — whether to treat emulators as high threat.
  /// [failOnDebugger] — whether to treat debugger as high threat.
  /// [customSuPaths] — additional su binary paths to scan.
  static Future<void> configure({
    bool failOnEmulator = false,
    bool failOnDebugger = false,
    List<String> customSuPaths = const [],
    List<String> customJailbreakPaths = const [],
  }) async {
    try {
      await _channel.invokeMethod('configure', {
        'failOnEmulator': failOnEmulator,
        'failOnDebugger': failOnDebugger,
        'customSuPaths': customSuPaths,
        'customJailbreakPaths': customJailbreakPaths,
      });
    } on PlatformException catch (e) {
      debugPrint('[SecureShield] configure error: ${e.message}');
      rethrow;
    }
  }
}

extension on TargetPlatform {
  bool get isAndroid => this == TargetPlatform.android;
  bool get isIOS => this == TargetPlatform.iOS;
}
