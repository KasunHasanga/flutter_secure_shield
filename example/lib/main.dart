import 'package:flutter/material.dart';
import 'package:flutter_secure_shield/secure_shield.dart';

void main() {
  runApp(const SecureShieldDemoApp());
}

class SecureShieldDemoApp extends StatelessWidget {
  const SecureShieldDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureShield Demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true).copyWith(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF00FF88),
          brightness: Brightness.dark,
        ),
      ),
      home: const ScanScreen(),
    );
  }
}

class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});

  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  DetectionResult? _result;
  bool _scanning = false;

  Future<void> _runScan() async {
    setState(() {
      _scanning = true;
      _result = null;
    });

    // Configure first
    await SecureShield.configure(
      failOnEmulator: false,
      failOnDebugger: false,
    );

    // Run full scan
    final result = await SecureShield.performFullScan();
    setState(() {
      _result = result;
      _scanning = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E1A),
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        title: const Text(
          '🛡 SecureShield',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        centerTitle: true,
      ),
      body: _scanning
          ? const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Color(0xFF00FF88)),
                  SizedBox(height: 16),
                  Text('Scanning device...',
                      style: TextStyle(color: Colors.white70)),
                ],
              ),
            )
          : _result == null
              ? _buildWelcome()
              : _buildResults(),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _scanning ? null : _runScan,
        backgroundColor: const Color(0xFF00FF88),
        foregroundColor: Colors.black,
        icon: const Icon(Icons.security),
        label: Text(_scanning ? 'Scanning…' : 'Run Scan'),
      ),
    );
  }

  Widget _buildWelcome() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.shield_outlined, size: 80, color: Color(0xFF00FF88)),
          const SizedBox(height: 24),
          const Text(
            'Advanced Security Scanner',
            style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text(
            'Tap Run Scan to check device security',
            style: TextStyle(color: Colors.white54),
          ),
        ],
      ),
    );
  }

  Widget _buildResults() {
    final result = _result!;
    final color = _threatColor(result.overallThreatLevel);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Overall status card
        Card(
          color: color.withOpacity(0.15),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: BorderSide(color: color, width: 1.5),
          ),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              children: [
                Icon(
                  result.isSafe ? Icons.verified_user : Icons.warning_amber,
                  size: 48,
                  color: color,
                ),
                const SizedBox(height: 12),
                Text(
                  result.overallThreatLevel.label,
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  result.isSafe
                      ? 'Device appears secure'
                      : '${result.detectedThreats.length} threat(s) detected',
                  style: const TextStyle(color: Colors.white70),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  children: [
                    _chip('Rooted: ${result.isRooted ? "YES" : "NO"}',
                        result.isRooted ? Colors.red : Colors.green),
                    _chip('Emulator: ${result.isEmulator ? "YES" : "NO"}',
                        result.isEmulator ? Colors.orange : Colors.green),
                    _chip('Debugger: ${result.isDebuggerAttached ? "YES" : "NO"}',
                        result.isDebuggerAttached ? Colors.orange : Colors.green),
                  ],
                )
              ],
            ),
          ),
        ),
        const SizedBox(height: 20),
        const Text(
          'Check Results',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 12),
        ...result.checks.map((check) => _buildCheckTile(check)),
      ],
    );
  }

  Widget _buildCheckTile(CheckResult check) {
    final color = _threatColor(check.threatLevel);
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      color: const Color(0xFF141824),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: color.withOpacity(0.2),
          child: Icon(
            check.detected ? Icons.warning : Icons.check,
            color: color,
            size: 18,
          ),
        ),
        title: Text(check.type.displayName,
            style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
        subtitle: Text(check.description,
            style: const TextStyle(color: Colors.white54, fontSize: 12)),
        trailing: check.detected
            ? Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: color, width: 0.5),
                ),
                child: Text(
                  check.threatLevel.label,
                  style: TextStyle(
                      color: color,
                      fontSize: 10,
                      fontWeight: FontWeight.bold),
                ),
              )
            : null,
      ),
    );
  }

  Widget _chip(String label, Color color) {
    return Chip(
      label: Text(label,
          style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.bold)),
      backgroundColor: color.withOpacity(0.15),
      side: BorderSide(color: color.withOpacity(0.5)),
      padding: EdgeInsets.zero,
      visualDensity: VisualDensity.compact,
    );
  }

  Color _threatColor(ThreatLevel level) {
    switch (level) {
      case ThreatLevel.none:
        return const Color(0xFF00FF88);
      case ThreatLevel.low:
        return const Color(0xFF88AAFF);
      case ThreatLevel.medium:
        return const Color(0xFFFFCC00);
      case ThreatLevel.high:
        return const Color(0xFFFF6600);
      case ThreatLevel.critical:
        return const Color(0xFFFF2244);
    }
  }
}
