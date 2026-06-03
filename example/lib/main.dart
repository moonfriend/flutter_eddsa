import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_eddsa/flutter_eddsa.dart';

void main() {
  runApp(const EddsaExampleApp());
}

class EddsaExampleApp extends StatelessWidget {
  const EddsaExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'flutter_eddsa demo',
      theme: ThemeData(colorSchemeSeed: Colors.indigo),
      home: DefaultTabController(
        length: 1,
        child: Scaffold(
          appBar: AppBar(
            title: const Text('flutter_eddsa'),
            bottom: const TabBar(
              tabs: [
                Tab(text: 'Key derivation'),
              ],
            ),
          ),
          body: const TabBarView(
            children: [
              KeyDerivationPage(),
            ],
          ),
        ),
      ),
    );
  }
}

// ─── Tab 1: derivePublicKey ──────────────────────────────────────────────────

class KeyDerivationPage extends StatefulWidget {
  const KeyDerivationPage({super.key});

  @override
  State<KeyDerivationPage> createState() => _KeyDerivationPageState();
}

class _KeyDerivationPageState extends State<KeyDerivationPage> {
  final _secretController = TextEditingController();
  String _publicKeyHex = '';
  String _error = '';

  void _derive() {
    setState(() {
      _publicKeyHex = '';
      _error = '';
    });
    try {
      final Uint8List secret = EddsaUtils.bytesFromHex(_secretController.text.trim());
      final Uint8List pub    = Ed25519.derivePublicKey(secret);
      setState(() => _publicKeyHex = EddsaUtils.hexFromBytes(pub));
    } catch (e) {
      setState(() => _error = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Enter a 32-byte secret key as hex (64 hex chars):'),
          const SizedBox(height: 8),
          TextField(
            controller: _secretController,
            decoration: const InputDecoration(
              border: OutlineInputBorder(),
              hintText: '9d61b19d...',
            ),
          ),
          const SizedBox(height: 12),
          ElevatedButton(
            onPressed: _derive,
            child: const Text('Derive public key'),
          ),
          const SizedBox(height: 16),
          if (_error.isNotEmpty)
            Text(_error, style: const TextStyle(color: Colors.red)),
          if (_publicKeyHex.isNotEmpty) ...[
            const Text('Public key (hex):',
                style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            SelectableText(_publicKeyHex,
                style: const TextStyle(fontFamily: 'monospace')),
          ],
        ],
      ),
    );
  }
}
