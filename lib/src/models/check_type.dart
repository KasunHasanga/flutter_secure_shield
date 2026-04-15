/// Represents the type of security check performed
enum CheckType {
  // Android-specific
  suBinaries,
  dangerousProps,
  rwPaths,
  testKeys,
  suExists,
  busyboxInstalled,
  magiskDetected,
  xposedDetected,
  seLinuxBypass,
  hookingFramework,
  emulatorDetected,
  adbEnabled,
  developerOptions,
  unknownSources,
  packageManager,
  buildTagsTest,

  // iOS-specific
  cydiaSources,
  jailbrokenPaths,
  sandboxViolation,
  dyldEnvironment,
  syscallCheck,
  substrateDylib,
  openSSHInstalled,
  unsignedCode,
  filePermissions,
  urlSchemes,

  // Cross-platform
  debuggerAttached,
  vpnActive,
  proxyDetected,
  screenshotDetected,
  remoteControl,
}

extension CheckTypeExtension on CheckType {
  bool get isAndroidOnly => [
        CheckType.suBinaries,
        CheckType.dangerousProps,
        CheckType.rwPaths,
        CheckType.testKeys,
        CheckType.suExists,
        CheckType.busyboxInstalled,
        CheckType.magiskDetected,
        CheckType.xposedDetected,
        CheckType.seLinuxBypass,
        CheckType.hookingFramework,
        CheckType.adbEnabled,
        CheckType.developerOptions,
        CheckType.unknownSources,
        CheckType.packageManager,
        CheckType.buildTagsTest,
      ].contains(this);

  bool get isIosOnly => [
        CheckType.cydiaSources,
        CheckType.jailbrokenPaths,
        CheckType.sandboxViolation,
        CheckType.dyldEnvironment,
        CheckType.syscallCheck,
        CheckType.substrateDylib,
        CheckType.openSSHInstalled,
        CheckType.unsignedCode,
        CheckType.filePermissions,
        CheckType.urlSchemes,
      ].contains(this);

  String get displayName {
    switch (this) {
      case CheckType.suBinaries:
        return 'SU Binaries Check';
      case CheckType.dangerousProps:
        return 'Dangerous System Props';
      case CheckType.rwPaths:
        return 'RW System Paths';
      case CheckType.testKeys:
        return 'Test Keys Build';
      case CheckType.suExists:
        return 'SU Binary Exists';
      case CheckType.busyboxInstalled:
        return 'BusyBox Installed';
      case CheckType.magiskDetected:
        return 'Magisk Detected';
      case CheckType.xposedDetected:
        return 'Xposed Framework';
      case CheckType.seLinuxBypass:
        return 'SELinux Bypass';
      case CheckType.hookingFramework:
        return 'Hooking Framework';
      case CheckType.emulatorDetected:
        return 'Emulator Detected';
      case CheckType.adbEnabled:
        return 'ADB Enabled';
      case CheckType.developerOptions:
        return 'Developer Options';
      case CheckType.unknownSources:
        return 'Unknown Sources';
      case CheckType.packageManager:
        return 'Suspicious Packages';
      case CheckType.buildTagsTest:
        return 'Build Tags Test';
      case CheckType.cydiaSources:
        return 'Cydia Sources';
      case CheckType.jailbrokenPaths:
        return 'Jailbreak Paths';
      case CheckType.sandboxViolation:
        return 'Sandbox Violation';
      case CheckType.dyldEnvironment:
        return 'DYLD Environment';
      case CheckType.syscallCheck:
        return 'Syscall Check';
      case CheckType.substrateDylib:
        return 'Substrate Dylib';
      case CheckType.openSSHInstalled:
        return 'OpenSSH Installed';
      case CheckType.unsignedCode:
        return 'Unsigned Code';
      case CheckType.filePermissions:
        return 'File Permissions';
      case CheckType.urlSchemes:
        return 'Suspicious URL Schemes';
      case CheckType.debuggerAttached:
        return 'Debugger Attached';
      case CheckType.vpnActive:
        return 'VPN Active';
      case CheckType.proxyDetected:
        return 'Proxy Detected';
      case CheckType.screenshotDetected:
        return 'Screenshot Detected';
      case CheckType.remoteControl:
        return 'Remote Control';
    }
  }
}
