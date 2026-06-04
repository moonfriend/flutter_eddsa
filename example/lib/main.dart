/// Example: X25519 Diffie-Hellman key exchange with flutter_eddsa.
///
/// Two parties (Alice and Bob) each generate a key pair independently.
/// They exchange public keys over an untrusted channel and each computes
/// the same shared secret — without ever transmitting a private key.

import 'package:flutter/material.dart';
import 'package:flutter_eddsa/flutter_eddsa.dart';

void main() {
  runApp(const DhExampleApp());
}

class DhExampleApp extends StatelessWidget {
  const DhExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'flutter_eddsa — DH example',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: const DhExamplePage(),
    );
  }
}

class DhExamplePage extends StatefulWidget {
  const DhExamplePage({super.key});

  @override
  State<DhExamplePage> createState() => _DhExamplePageState();
}

class _DhExamplePageState extends State<DhExamplePage> {
  _DhResult? _result;

  void _run() {
    // ── Alice ────────────────────────────────────────────────────────────
    final aliceSecret = EddsaUtils.generateRandom32();
    final alicePublic  = Ed25519.generateX25519PublicKey(aliceSecret);

    // ── Bob ──────────────────────────────────────────────────────────────
    final bobSecret = EddsaUtils.generateRandom32();
    final bobPublic  = Ed25519.generateX25519PublicKey(bobSecret);

    // ── Key agreement ────────────────────────────────────────────────────
    // Each side uses their own secret + the peer's public key.
    // The result is identical on both sides.
    final aliceShared = Ed25519.diffieHellman(aliceSecret, bobPublic);
    final bobShared   = Ed25519.diffieHellman(bobSecret,   alicePublic);

    setState(() {
      _result = _DhResult(
        alicePublic:  EddsaUtils.hexFromBytes(alicePublic),
        bobPublic:    EddsaUtils.hexFromBytes(bobPublic),
        aliceShared:  EddsaUtils.hexFromBytes(aliceShared),
        bobShared:    EddsaUtils.hexFromBytes(bobShared),
        match:        EddsaUtils.hexFromBytes(aliceShared) ==
                      EddsaUtils.hexFromBytes(bobShared),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final r = _result;
    return Scaffold(
      appBar: AppBar(title: const Text('Diffie-Hellman key exchange')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Alice and Bob each generate a key pair, exchange public keys, '
              'and independently compute the same shared secret — '
              'without ever transmitting a private key.',
              style: TextStyle(fontSize: 14, height: 1.5),
            ),
            const SizedBox(height: 24),
            Center(
              child: FilledButton.icon(
                onPressed: _run,
                icon: const Icon(Icons.sync),
                label: const Text('Run key exchange'),
              ),
            ),
            if (r != null) ...[
              const SizedBox(height: 32),
              _Section('Alice\'s public key',  r.alicePublic),
              _Section('Bob\'s public key',    r.bobPublic),
              const Divider(height: 32),
              _Section('Alice\'s shared secret', r.aliceShared),
              _Section('Bob\'s shared secret',   r.bobShared),
              const SizedBox(height: 16),
              Row(
                children: [
                  Icon(
                    r.match ? Icons.check_circle : Icons.cancel,
                    color: r.match ? Colors.green : Colors.red,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    r.match
                        ? 'Shared secrets match — key exchange successful'
                        : 'Mismatch — something went wrong',
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                      color: r.match ? Colors.green : Colors.red,
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _DhResult {
  final String alicePublic;
  final String bobPublic;
  final String aliceShared;
  final String bobShared;
  final bool   match;

  const _DhResult({
    required this.alicePublic,
    required this.bobPublic,
    required this.aliceShared,
    required this.bobShared,
    required this.match,
  });
}

class _Section extends StatelessWidget {
  final String label;
  final String value;

  const _Section(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
          const SizedBox(height: 4),
          SelectableText(
            value,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
          ),
        ],
      ),
    );
  }
}
