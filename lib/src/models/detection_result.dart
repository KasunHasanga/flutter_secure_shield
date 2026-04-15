import 'threat_level.dart';
import 'check_type.dart';

/// Result of a single security check
class CheckResult {
  final CheckType type;
  final bool detected;
  final ThreatLevel threatLevel;
  final String description;
  final Map<String, dynamic>? metadata;

  const CheckResult({
    required this.type,
    required this.detected,
    required this.threatLevel,
    required this.description,
    this.metadata,
  });

  factory CheckResult.fromMap(Map<String, dynamic> map) {
    return CheckResult(
      type: CheckType.values.firstWhere(
        (e) => e.name == map['type'],
        orElse: () => CheckType.debuggerAttached,
      ),
      detected: map['detected'] as bool,
      threatLevel: ThreatLevel.values.firstWhere(
        (e) => e.name == map['threatLevel'],
        orElse: () => ThreatLevel.none,
      ),
      description: map['description'] as String,
      metadata: map['metadata'] as Map<String, dynamic>?,
    );
  }

  Map<String, dynamic> toMap() => {
        'type': type.name,
        'detected': detected,
        'threatLevel': threatLevel.name,
        'description': description,
        if (metadata != null) 'metadata': metadata,
      };

  @override
  String toString() =>
      'CheckResult(type: ${type.displayName}, detected: $detected, level: ${threatLevel.label})';
}

/// Comprehensive result of a full device security scan
class DetectionResult {
  /// Whether any root/jailbreak was detected
  final bool isRooted;

  /// Whether running on an emulator/simulator
  final bool isEmulator;

  /// Whether a debugger is attached
  final bool isDebuggerAttached;

  /// Overall threat level for the device
  final ThreatLevel overallThreatLevel;

  /// Detailed results per check
  final List<CheckResult> checks;

  /// Timestamp of the scan
  final DateTime scannedAt;

  /// Platform (android / ios)
  final String platform;

  const DetectionResult({
    required this.isRooted,
    required this.isEmulator,
    required this.isDebuggerAttached,
    required this.overallThreatLevel,
    required this.checks,
    required this.scannedAt,
    required this.platform,
  });

  /// All checks that detected a threat
  List<CheckResult> get detectedThreats =>
      checks.where((c) => c.detected).toList();

  /// Whether the device is considered safe to run in
  bool get isSafe => overallThreatLevel == ThreatLevel.none;

  factory DetectionResult.fromMap(Map<String, dynamic> map) {
    return DetectionResult(
      isRooted: map['isRooted'] as bool,
      isEmulator: map['isEmulator'] as bool,
      isDebuggerAttached: map['isDebuggerAttached'] as bool,
      overallThreatLevel: ThreatLevel.values.firstWhere(
        (e) => e.name == map['overallThreatLevel'],
        orElse: () => ThreatLevel.none,
      ),
      checks: (map['checks'] as List<dynamic>)
          .map((c) => CheckResult.fromMap(Map<String, dynamic>.from(c as Map)))
          .toList(),
      scannedAt: DateTime.fromMillisecondsSinceEpoch(map['scannedAt'] as int),
      platform: map['platform'] as String,
    );
  }

  Map<String, dynamic> toMap() => {
        'isRooted': isRooted,
        'isEmulator': isEmulator,
        'isDebuggerAttached': isDebuggerAttached,
        'overallThreatLevel': overallThreatLevel.name,
        'checks': checks.map((c) => c.toMap()).toList(),
        'scannedAt': scannedAt.millisecondsSinceEpoch,
        'platform': platform,
      };

  @override
  String toString() =>
      'DetectionResult(rooted: $isRooted, emulator: $isEmulator, '
      'threat: ${overallThreatLevel.label}, threats: ${detectedThreats.length})';
}
