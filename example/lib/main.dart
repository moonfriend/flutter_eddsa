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
        length: 6,
        child: Scaffold(
          appBar: AppBar(
            title: const Text('flutter_eddsa'),
            bottom: const TabBar(
              isScrollable: true,
              tabs: [
                Tab(text: 'Key derivation'),
                Tab(text: 'Sign'),
                Tab(text: 'Verify'),
                Tab(text: 'DH key gen'),
                Tab(text: 'Diffie-Hellman'),
                Tab(text: 'Key convert'),
              ],
            ),
          ),
          body: const TabBarView(
            children: [
              KeyDerivationPage(),
              SignPage(),
              VerifyPage(),
              DhKeyGenPage(),
              DiffieHellmanPage(),
              KeyConversionPage(),
            ],
          ),
        ),
      ),
    );
  }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

Widget _label(String text) =>
    Text(text, style: const TextStyle(fontWeight: FontWeight.bold));

Widget _field(TextEditingController ctrl, String hint) => TextField(
      controller: ctrl,
      decoration:
          InputDecoration(border: const OutlineInputBorder(), hintText: hint),
    );

Widget _result(String label, String value) => Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 4),
        SelectableText(value,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
      ],
    );

Widget _error(String msg) =>
    Text(msg, style: const TextStyle(color: Colors.red));

// ─── Tab 1: derivePublicKey ───────────────────────────────────────────────────

class KeyDerivationPage extends StatefulWidget {
  const KeyDerivationPage({super.key});
  @override
  State<KeyDerivationPage> createState() => _KeyDerivationPageState();
}

class _KeyDerivationPageState extends State<KeyDerivationPage> {
  final _sec = TextEditingController();
  String _pub = '', _err = '';

  void _run() {
    setState(() { _pub = ''; _err = ''; });
    try {
      final pub = Ed25519.derivePublicKey(EddsaUtils.bytesFromHex(_sec.text.trim()));
      setState(() => _pub = EddsaUtils.hexFromBytes(pub));
    } catch (e) { setState(() => _err = e.toString()); }
  }

  @override
  Widget build(BuildContext context) => _page([
    _label('Secret key (hex, 64 chars)'),
    const SizedBox(height: 6),
    _field(_sec, '9d61b19d...'),
    const SizedBox(height: 12),
    ElevatedButton(onPressed: _run, child: const Text('Derive public key')),
    const SizedBox(height: 16),
    if (_err.isNotEmpty) _error(_err),
    if (_pub.isNotEmpty) _result('Public key:', _pub),
  ]);
}

// ─── Tab 2: signMessage ───────────────────────────────────────────────────────

class SignPage extends StatefulWidget {
  const SignPage({super.key});
  @override
  State<SignPage> createState() => _SignPageState();
}

class _SignPageState extends State<SignPage> {
  final _sec = TextEditingController();
  final _pub = TextEditingController();
  final _msg = TextEditingController();
  String _sig = '', _err = '';

  void _run() {
    setState(() { _sig = ''; _err = ''; });
    try {
      final sig = Ed25519.signMessage(
        EddsaUtils.bytesFromHex(_sec.text.trim()),
        EddsaUtils.bytesFromHex(_pub.text.trim()),
        EddsaUtils.bytesFromString(_msg.text),
      );
      setState(() => _sig = EddsaUtils.hexFromBytes(sig));
    } catch (e) { setState(() => _err = e.toString()); }
  }

  @override
  Widget build(BuildContext context) => _page([
    _label('Secret key (hex)'),   const SizedBox(height: 6),
    _field(_sec, '9d61b19d...'),  const SizedBox(height: 12),
    _label('Public key (hex)'),   const SizedBox(height: 6),
    _field(_pub, 'd75a9801...'),  const SizedBox(height: 12),
    _label('Message'),            const SizedBox(height: 6),
    _field(_msg, 'Hello world'),  const SizedBox(height: 12),
    ElevatedButton(onPressed: _run, child: const Text('Sign message')),
    const SizedBox(height: 16),
    if (_err.isNotEmpty) _error(_err),
    if (_sig.isNotEmpty) _result('Signature (64 bytes):', _sig),
  ]);
}

// ─── Tab 3: verifySignature ───────────────────────────────────────────────────

class VerifyPage extends StatefulWidget {
  const VerifyPage({super.key});
  @override
  State<VerifyPage> createState() => _VerifyPageState();
}

class _VerifyPageState extends State<VerifyPage> {
  final _sig = TextEditingController();
  final _pub = TextEditingController();
  final _msg = TextEditingController();
  String _result = '', _err = '';

  void _run() {
    setState(() { _result = ''; _err = ''; });
    try {
      final ok = Ed25519.verifySignature(
        EddsaUtils.bytesFromHex(_sig.text.trim()),
        EddsaUtils.bytesFromHex(_pub.text.trim()),
        EddsaUtils.bytesFromString(_msg.text),
      );
      setState(() => _result = ok ? '✓  Valid signature' : '✗  Invalid signature');
    } catch (e) { setState(() => _err = e.toString()); }
  }

  @override
  Widget build(BuildContext context) => _page([
    _label('Signature (hex, 128 chars)'), const SizedBox(height: 6),
    _field(_sig, 'e5564300...'),          const SizedBox(height: 12),
    _label('Public key (hex)'),           const SizedBox(height: 6),
    _field(_pub, 'd75a9801...'),          const SizedBox(height: 12),
    _label('Message'),                    const SizedBox(height: 6),
    _field(_msg, 'Hello world'),          const SizedBox(height: 12),
    ElevatedButton(onPressed: _run, child: const Text('Verify signature')),
    const SizedBox(height: 16),
    if (_err.isNotEmpty) _error(_err),
    if (_result.isNotEmpty)
      Text(_result,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: _result.startsWith('✓') ? Colors.green : Colors.red,
          )),
  ]);
}

// ─── Tab 4: generateX25519PublicKey ──────────────────────────────────────────

class DhKeyGenPage extends StatefulWidget {
  const DhKeyGenPage({super.key});
  @override
  State<DhKeyGenPage> createState() => _DhKeyGenPageState();
}

class _DhKeyGenPageState extends State<DhKeyGenPage> {
  final _scalar = TextEditingController();
  String _pub = '', _err = '';

  void _run() {
    setState(() { _pub = ''; _err = ''; });
    try {
      final pub = Ed25519.generateX25519PublicKey(
          EddsaUtils.bytesFromHex(_scalar.text.trim()));
      setState(() => _pub = EddsaUtils.hexFromBytes(pub));
    } catch (e) { setState(() => _err = e.toString()); }
  }

  @override
  Widget build(BuildContext context) => _page([
    _label('Secret scalar (hex, 64 chars)'),
    const SizedBox(height: 6),
    _field(_scalar, '4a385b1e...'),
    const SizedBox(height: 12),
    ElevatedButton(onPressed: _run, child: const Text('Generate X25519 public key')),
    const SizedBox(height: 16),
    if (_err.isNotEmpty) _error(_err),
    if (_pub.isNotEmpty) _result('X25519 public key:', _pub),
  ]);
}

// ─── Tab 5: diffieHellman ─────────────────────────────────────────────────────

class DiffieHellmanPage extends StatefulWidget {
  const DiffieHellmanPage({super.key});
  @override
  State<DiffieHellmanPage> createState() => _DiffieHellmanPageState();
}

class _DiffieHellmanPageState extends State<DiffieHellmanPage> {
  final _sec  = TextEditingController();
  final _peer = TextEditingController();
  String _shared = '', _err = '';

  void _run() {
    setState(() { _shared = ''; _err = ''; });
    try {
      final ss = Ed25519.diffieHellman(
        EddsaUtils.bytesFromHex(_sec.text.trim()),
        EddsaUtils.bytesFromHex(_peer.text.trim()),
      );
      setState(() => _shared = EddsaUtils.hexFromBytes(ss));
    } catch (e) { setState(() => _err = e.toString()); }
  }

  @override
  Widget build(BuildContext context) => _page([
    _label('Your secret scalar (hex)'),  const SizedBox(height: 6),
    _field(_sec,  '4a385b1e...'),         const SizedBox(height: 12),
    _label("Peer's X25519 public key (hex)"), const SizedBox(height: 6),
    _field(_peer, '9c8bf8f7...'),         const SizedBox(height: 12),
    ElevatedButton(onPressed: _run, child: const Text('Compute shared secret')),
    const SizedBox(height: 16),
    if (_err.isNotEmpty) _error(_err),
    if (_shared.isNotEmpty) _result('Shared secret:', _shared),
  ]);
}

// ─── Tab 6: key conversion ────────────────────────────────────────────────────

class KeyConversionPage extends StatefulWidget {
  const KeyConversionPage({super.key});
  @override
  State<KeyConversionPage> createState() => _KeyConversionPageState();
}

class _KeyConversionPageState extends State<KeyConversionPage> {
  final _edSec = TextEditingController();
  final _edPub = TextEditingController();
  String _x25519Sec = '', _x25519Pub = '', _err = '';

  void _run() {
    setState(() { _x25519Sec = ''; _x25519Pub = ''; _err = ''; });
    try {
      final xSec = Ed25519.secretKeyToX25519(
          EddsaUtils.bytesFromHex(_edSec.text.trim()));
      final xPub = Ed25519.publicKeyToX25519(
          EddsaUtils.bytesFromHex(_edPub.text.trim()));
      setState(() {
        _x25519Sec = EddsaUtils.hexFromBytes(xSec);
        _x25519Pub = EddsaUtils.hexFromBytes(xPub);
      });
    } catch (e) { setState(() => _err = e.toString()); }
  }

  @override
  Widget build(BuildContext context) => _page([
    _label('Ed25519 secret key (hex)'), const SizedBox(height: 6),
    _field(_edSec, '9d61b19d...'),      const SizedBox(height: 12),
    _label('Ed25519 public key (hex)'), const SizedBox(height: 6),
    _field(_edPub, 'd75a9801...'),      const SizedBox(height: 12),
    ElevatedButton(onPressed: _run, child: const Text('Convert to X25519')),
    const SizedBox(height: 16),
    if (_err.isNotEmpty) _error(_err),
    if (_x25519Sec.isNotEmpty) ...[
      _result('X25519 secret key:', _x25519Sec),
      const SizedBox(height: 12),
      _result('X25519 public key:', _x25519Pub),
    ],
  ]);
}

// ─── shared page wrapper ─────────────────────────────────────────────────────

Widget _page(List<Widget> children) => SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: children,
      ),
    );
