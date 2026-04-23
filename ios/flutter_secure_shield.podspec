Pod::Spec.new do |s|
  s.name             = 'flutter_secure_shield'
  s.version          = '1.0.2'
  s.summary          = 'Advanced root and jailbreak detection Flutter plugin.'
  s.description      = <<-DESC
    SecureShield provides comprehensive root detection (Android) and
    jailbreak detection (iOS) checks including Magisk, Xposed, Cydia,
    Substrate, emulator, debugger, VPN and proxy detection.
  DESC
  s.homepage         = 'https://github.com/KasunHasanga/flutter_secure_shield'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'SecureShield' => 'dev@secureshield.io' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform         = :ios, '13.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version    = '5.0'
end
