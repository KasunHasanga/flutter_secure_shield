/// Represents the severity level of a detected threat
enum ThreatLevel {
  /// No threat detected
  none,

  /// Low-risk indicators found (e.g., developer options enabled)
  low,

  /// Medium-risk indicators found (e.g., unknown sources enabled)
  medium,

  /// High-risk indicators found (e.g., root/jailbreak detected)
  high,

  /// Critical threat — device is definitively compromised
  critical,
}

extension ThreatLevelExtension on ThreatLevel {
  bool get isSafe => this == ThreatLevel.none;
  bool get isCompromised => index >= ThreatLevel.high.index;

  String get label {
    switch (this) {
      case ThreatLevel.none:
        return 'SECURE';
      case ThreatLevel.low:
        return 'LOW RISK';
      case ThreatLevel.medium:
        return 'MEDIUM RISK';
      case ThreatLevel.high:
        return 'HIGH RISK';
      case ThreatLevel.critical:
        return 'CRITICAL';
    }
  }
}
