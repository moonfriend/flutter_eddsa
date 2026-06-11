import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_eddsa/flutter_eddsa.dart';

void main() => runApp(const DemoApp());

class DemoApp extends StatelessWidget {
  const DemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'flutter_eddsa demo',
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: const DemoPage(),
    );
  }
}

// ─── Reusable hex display with copy button ───────────────────────────────────

class _HexField extends StatelessWidget {
  final String label;
  final String hex;

  const _HexField({required this.label, required this.hex});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                label,
                style: const TextStyle(
                  fontWeight: FontWeight.bold,
                  fontSize: 13,
                ),
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.copy, size: 18),
                tooltip: 'Copy to clipboard',
                visualDensity: VisualDensity.compact,
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: hex));
                  ScaffoldMessenger.of(context)
                    ..hideCurrentSnackBar()
                    ..showSnackBar(
                      SnackBar(
                        content: Text('$label copied'),
                        duration: const Duration(seconds: 1),
                        behavior: SnackBarBehavior.floating,
                      ),
                    );
                },
              ),
            ],
          ),
          SelectableText(
            hex,
            style: const TextStyle(
              fontFamily: 'monospace',
              fontSize: 11.5,
              height: 1.5,
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Section card ─────────────────────────────────────────────────────────────

class _SectionCard extends StatelessWidget {
  final String title;
  final Widget child;

  const _SectionCard({required this.title, required this.child});

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: Theme.of(
                context,
              ).textTheme.titleMedium!.copyWith(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}

// ─── Demo page ────────────────────────────────────────────────────────────────

class DemoPage extends StatefulWidget {
  const DemoPage({super.key});

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  // Step 1
  SecretKey? _secretKey;
  Uint8List? _publicKey;

  // Step 2
  final _msgCtrl = TextEditingController(text: 'Hello, flutter_eddsa!');
  Uint8List? _signature;

  // Step 3
  bool? _verifyResult;
  bool _verifiedTampered = false;
  String? _verifiedMessage;

  // Step 4
  SecretKey? _laylaSec;
  Uint8List? _laylaPub;
  SecretKey? _yusufSec;
  Uint8List? _yusufPub;
  SecretKey? _laylaShared;
  SecretKey? _yusufShared;

  @override
  void dispose() {
    _secretKey?.dispose();
    _laylaSec?.dispose();
    _yusufSec?.dispose();
    _laylaShared?.dispose();
    _yusufShared?.dispose();
    _msgCtrl.dispose();
    super.dispose();
  }

  void _generateKeys() {
    final sk = SecretKey.generate();
    final pk = Ed25519.derivePublicKey(sk);
    _secretKey?.dispose();
    setState(() {
      _secretKey = sk;
      _publicKey = pk;
      _signature = null;
      _verifyResult = null;
      _verifiedTampered = false;
    });
  }

  void _sign() {
    final sk = _secretKey;
    final pk = _publicKey;
    if (sk == null || pk == null) return;
    final sig = Ed25519.signMessage(sk, pk, utf8.encode(_msgCtrl.text));
    setState(() {
      _signature = sig;
      _verifyResult = null;
      _verifiedTampered = false;
    });
  }

  void _verify({required bool tamper}) {
    final sig = _signature;
    final pk = _publicKey;
    if (sig == null || pk == null) return;
    final text = tamper ? '${_msgCtrl.text} (tampered)' : _msgCtrl.text;
    setState(() {
      _verifyResult = Ed25519.verifySignature(sig, pk, utf8.encode(text));
      _verifiedTampered = tamper;
      _verifiedMessage = text;
    });
  }

  void _runDH() {
    final aSec = SecretKey.generate();
    final aPub = Ed25519.generateX25519PublicKey(aSec);
    final bSec = SecretKey.generate();
    final bPub = Ed25519.generateX25519PublicKey(bSec);
    final aShared = Ed25519.diffieHellman(aSec, bPub);
    final bShared = Ed25519.diffieHellman(bSec, aPub);
    _laylaSec?.dispose();
    _yusufSec?.dispose();
    _laylaShared?.dispose();
    _yusufShared?.dispose();
    setState(() {
      _laylaSec = aSec;
      _laylaPub = aPub;
      _yusufSec = bSec;
      _yusufPub = bPub;
      _laylaShared = aShared;
      _yusufShared = bShared;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('flutter_eddsa demo'),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            tooltip: 'How DH works (color metaphor)',
            onPressed:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const ColorPage()),
                ),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            _buildKeyCard(),
            _buildSignCard(),
            _buildVerifyCard(),
            _buildDHCard(),
          ],
        ),
      ),
    );
  }

  // ── Section 1: Key pair ──────────────────────────────────────────────────

  Widget _buildKeyCard() {
    final sk = _secretKey;
    final pk = _publicKey;
    return _SectionCard(
      title: '1 · Generate key pair',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Generates a cryptographically random 32-byte secret key and '
            'derives the corresponding Ed25519 public key.',
            style: TextStyle(fontSize: 13, height: 1.5),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: _generateKeys,
            icon: const Icon(Icons.key),
            label: Text(sk == null ? 'Generate' : 'Regenerate'),
          ),
          if (sk != null && pk != null) ...[
            const SizedBox(height: 16),
            _HexField(
              label: 'Secret key (never share this — shown here for demo only)',
              hex: EddsaUtils.hexFromBytes(sk.toBytes()),
            ),
            _HexField(label: 'Public key', hex: EddsaUtils.hexFromBytes(pk)),
          ],
        ],
      ),
    );
  }

  // ── Section 2: Sign ──────────────────────────────────────────────────────

  Widget _buildSignCard() {
    final sig = _signature;
    final canSign = _secretKey != null;
    return _SectionCard(
      title: '2 · Sign a message',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Edit the message, then sign it with the secret key. '
            'The 64-byte signature is unique to this key + message pair — '
            'changing even one character produces a completely different signature.',
            style: TextStyle(fontSize: 13, height: 1.5),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _msgCtrl,
            decoration: const InputDecoration(
              labelText: 'Message',
              border: OutlineInputBorder(),
            ),
            onChanged:
                (_) => setState(() {
                  _signature = null;
                  _verifyResult = null;
                }),
          ),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: canSign ? _sign : null,
            icon: const Icon(Icons.draw),
            label: const Text('Sign'),
          ),
          if (!canSign)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'Complete step 1 first.',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
            ),
          if (sig != null) ...[
            const SizedBox(height: 16),
            _HexField(
              label: 'Signature (64 bytes)',
              hex: EddsaUtils.hexFromBytes(sig),
            ),
          ],
        ],
      ),
    );
  }

  // ── Section 3: Verify ────────────────────────────────────────────────────

  Widget _buildVerifyCard() {
    final sig = _signature;
    final pk = _publicKey;
    final canVerify = sig != null && pk != null;
    final result = _verifyResult;
    final verifiedMsg = _verifiedMessage;

    return _SectionCard(
      title: '3 · Verify signature',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'verifySignature() takes three inputs and returns a boolean. '
            'Press "Verify original" to check the message as signed. '
            'Press "Verify tampered" to see the same signature rejected '
            'against a slightly different message.',
            style: TextStyle(fontSize: 13, height: 1.5),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: canVerify ? () => _verify(tamper: false) : null,
                icon: const Icon(Icons.verified),
                label: const Text('Verify original'),
              ),
              OutlinedButton.icon(
                onPressed: canVerify ? () => _verify(tamper: true) : null,
                icon: const Icon(Icons.edit_off),
                label: const Text('Verify tampered'),
              ),
            ],
          ),
          if (!canVerify)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'Sign a message first.',
                style: TextStyle(fontSize: 12, color: Colors.grey),
              ),
            ),
          if (result != null &&
              sig != null &&
              pk != null &&
              verifiedMsg != null) ...[
            const SizedBox(height: 16),
            _VerifyCallBox(
              sigHex: EddsaUtils.hexFromBytes(sig),
              pkHex: EddsaUtils.hexFromBytes(pk),
              message: verifiedMsg,
              tampered: _verifiedTampered,
              original: _msgCtrl.text,
              result: result,
            ),
          ],
        ],
      ),
    );
  }

  // ── Section 4: DH key exchange ───────────────────────────────────────────

  Widget _buildDHCard() {
    final aSec = _laylaSec;
    final aPub = _laylaPub;
    final bSec = _yusufSec;
    final bPub = _yusufPub;
    final aShared = _laylaShared;
    final bShared = _yusufShared;
    final hasResult =
        aSec != null &&
        aPub != null &&
        bSec != null &&
        bPub != null &&
        aShared != null &&
        bShared != null;

    return _SectionCard(
      title: '4 · X25519 Diffie-Hellman key exchange',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Layla and Yusuf each generate a secret key independently. '
            'They derive a public key from it and send only the public key '
            'over the network. Each then calls diffieHellman(own_secret, '
            'peer_public) — and both sides arrive at the same shared secret, '
            'without ever transmitting any private value.',
            style: TextStyle(fontSize: 13, height: 1.5),
          ),
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const ColorPage()),
                ),
            icon: const Icon(Icons.palette_outlined, size: 16),
            label: const Text(
              'See the color metaphor explanation →',
              style: TextStyle(fontSize: 12),
            ),
          ),
          const SizedBox(height: 4),
          FilledButton.icon(
            onPressed: _runDH,
            icon: const Icon(Icons.sync),
            label: Text(hasResult ? 'Run again' : 'Run exchange'),
          ),
          if (hasResult) ...[
            const SizedBox(height: 20),
            _DHProcess(
              laylaSec: EddsaUtils.hexFromBytes(aSec.toBytes()),
              laylaPub: EddsaUtils.hexFromBytes(aPub),
              yusufSec: EddsaUtils.hexFromBytes(bSec.toBytes()),
              yusufPub: EddsaUtils.hexFromBytes(bPub),
              laylaShared: EddsaUtils.hexFromBytes(aShared.toBytes()),
              yusufShared: EddsaUtils.hexFromBytes(bShared.toBytes()),
            ),
          ],
        ],
      ),
    );
  }
}

// ─── Verify call box ─────────────────────────────────────────────────────────

class _VerifyCallBox extends StatelessWidget {
  final String sigHex, pkHex, message, original;
  final bool tampered, result;

  const _VerifyCallBox({
    required this.sigHex,
    required this.pkHex,
    required this.message,
    required this.original,
    required this.tampered,
    required this.result,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    const mono = TextStyle(
      fontFamily: 'monospace',
      fontSize: 11.5,
      height: 1.6,
    );

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: cs.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Ed25519.verifySignature(', style: mono),
          // signature row
          _CallRow(
            label: '  signature  = ',
            value: sigHex,
            copyLabel: 'Signature',
            mono: mono,
          ),
          // publicKey row
          _CallRow(
            label: '  publicKey  = ',
            value: pkHex,
            copyLabel: 'Public key',
            mono: mono,
          ),
          // message row — highlight if tampered
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 2),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('  message    = ', style: mono),
                Expanded(
                  child: SelectableText(
                    '"$message"',
                    style: mono.copyWith(
                      color: tampered ? Colors.orange.shade700 : null,
                      fontWeight: tampered ? FontWeight.bold : null,
                    ),
                  ),
                ),
              ],
            ),
          ),
          if (tampered)
            Padding(
              padding: const EdgeInsets.only(left: 16, bottom: 2),
              child: Text(
                '// original was: "$original"',
                style: mono.copyWith(
                  color: cs.onSurfaceVariant,
                  fontStyle: FontStyle.italic,
                ),
              ),
            ),
          const Text(')', style: mono),
          const Divider(height: 20),
          Row(
            children: [
              Icon(
                result ? Icons.check_circle : Icons.cancel,
                color: result ? Colors.green : Colors.red,
                size: 22,
              ),
              const SizedBox(width: 8),
              Text(
                '→  ${result ? 'true' : 'false'}',
                style: mono.copyWith(
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                  color: result ? Colors.green : Colors.red,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  result
                      ? 'Signature is valid for this key and message.'
                      : tampered
                      ? 'Message was modified — signature no longer matches.'
                      : 'Signature does not match.',
                  style: TextStyle(
                    fontSize: 12,
                    color: result ? Colors.green : Colors.red,
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _CallRow extends StatelessWidget {
  final String label, value, copyLabel;
  final TextStyle mono;

  const _CallRow({
    required this.label,
    required this.value,
    required this.copyLabel,
    required this.mono,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: mono),
          Expanded(child: SelectableText(value, style: mono)),
          IconButton(
            icon: const Icon(Icons.copy, size: 15),
            tooltip: 'Copy $copyLabel',
            visualDensity: VisualDensity.compact,
            padding: EdgeInsets.zero,
            onPressed: () {
              Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context)
                ..hideCurrentSnackBar()
                ..showSnackBar(
                  SnackBar(
                    content: Text('$copyLabel copied'),
                    duration: const Duration(seconds: 1),
                    behavior: SnackBarBehavior.floating,
                  ),
                );
            },
          ),
        ],
      ),
    );
  }
}

// ─── DH process visualizer ────────────────────────────────────────────────────

class _DHProcess extends StatelessWidget {
  final String laylaSec, laylaPub, yusufSec, yusufPub, laylaShared, yusufShared;

  const _DHProcess({
    required this.laylaSec,
    required this.laylaPub,
    required this.yusufSec,
    required this.yusufPub,
    required this.laylaShared,
    required this.yusufShared,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final match = laylaShared == yusufShared;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // ── Step 1: Generate ──────────────────────────────────────────────
        _DHStepHeader(
          cs: cs,
          label: 'Step 1 · Each generates a key pair independently',
        ),
        const SizedBox(height: 8),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: _PartyBlock(
                name: 'Layla',
                icon: Icons.person,
                cs: cs,
                children: [
                  _DHHexRow('secret key 🔒', laylaSec, 'Layla secret', cs),
                  _DHArrow('generateX25519PublicKey(secret)'),
                  _DHHexRow('public key 📤', laylaPub, 'Layla public', cs),
                ],
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _PartyBlock(
                name: 'Yusuf',
                icon: Icons.person_2,
                cs: cs,
                children: [
                  _DHHexRow('secret key 🔒', yusufSec, 'Yusuf secret', cs),
                  _DHArrow('generateX25519PublicKey(secret)'),
                  _DHHexRow('public key 📤', yusufPub, 'Yusuf public', cs),
                ],
              ),
            ),
          ],
        ),

        // ── Step 2: Exchange ──────────────────────────────────────────────
        const SizedBox(height: 16),
        _DHStepHeader(
          cs: cs,
          label: 'Step 2 · Exchange public keys over the network',
        ),
        const SizedBox(height: 8),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(
            children: [
              _NetworkArrow(
                label: 'Layla sends layla_public → Yusuf',
                left: 'Layla',
                right: 'Yusuf',
                cs: cs,
              ),
              const SizedBox(height: 6),
              _NetworkArrow(
                label: 'Yusuf sends yusuf_public → Layla',
                left: 'Yusuf',
                right: 'Layla',
                cs: cs,
              ),
              const SizedBox(height: 8),
              Text(
                'An eavesdropper sees both public keys — but cannot derive '
                'either secret or the shared secret from them.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 11,
                  fontStyle: FontStyle.italic,
                  color: cs.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ),

        // ── Step 3: Compute shared secret ─────────────────────────────────
        const SizedBox(height: 16),
        _DHStepHeader(
          cs: cs,
          label: 'Step 3 · Each independently computes the shared secret',
        ),
        const SizedBox(height: 8),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: _PartyBlock(
                name: 'Layla',
                icon: Icons.person,
                cs: cs,
                children: [
                  _DHCallBox(
                    cs: cs,
                    call:
                        'diffieHellman(\n  layla_secret,\n  yusuf_public   ← received\n)',
                    resultHex: laylaShared,
                    copyLabel: 'Layla shared secret',
                  ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _PartyBlock(
                name: 'Yusuf',
                icon: Icons.person_2,
                cs: cs,
                children: [
                  _DHCallBox(
                    cs: cs,
                    call:
                        'diffieHellman(\n  yusuf_secret,\n  layla_public ← received\n)',
                    resultHex: yusufShared,
                    copyLabel: 'Yusuf shared secret',
                  ),
                ],
              ),
            ),
          ],
        ),

        // ── Result ────────────────────────────────────────────────────────
        const SizedBox(height: 16),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color:
                match
                    ? Colors.green.withValues(alpha: 0.08)
                    : Colors.red.withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(
              color: match ? Colors.green : Colors.red,
              width: 1.5,
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    match ? Icons.check_circle : Icons.cancel,
                    color: match ? Colors.green : Colors.red,
                    size: 22,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      match
                          ? 'diffieHellman(layla_secret, yusuf_public)\n'
                              '  == diffieHellman(yusuf_secret, layla_public)'
                          : 'Results do not match',
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        height: 1.5,
                      ),
                    ),
                  ),
                ],
              ),
              if (match) ...[
                const SizedBox(height: 10),
                _DHHexRow('shared secret', laylaShared, 'Shared secret', cs),
                const SizedBox(height: 6),
                Text(
                  'Both sides arrived at the same 32-byte value — '
                  'without ever transmitting a secret.',
                  style: TextStyle(fontSize: 12, color: Colors.green.shade700),
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }
}

class _DHStepHeader extends StatelessWidget {
  final ColorScheme cs;
  final String label;
  const _DHStepHeader({required this.cs, required this.label});

  @override
  Widget build(BuildContext context) {
    return Text(
      label,
      style: TextStyle(
        fontWeight: FontWeight.w600,
        fontSize: 12,
        color: cs.primary,
      ),
    );
  }
}

class _PartyBlock extends StatelessWidget {
  final String name;
  final IconData icon;
  final ColorScheme cs;
  final List<Widget> children;

  const _PartyBlock({
    required this.name,
    required this.icon,
    required this.cs,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: cs.primary),
              const SizedBox(width: 6),
              Text(
                name,
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  fontSize: 13,
                  color: cs.primary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...children,
        ],
      ),
    );
  }
}

class _DHHexRow extends StatelessWidget {
  final String label, hex, copyLabel;
  final ColorScheme cs;
  const _DHHexRow(this.label, this.hex, this.copyLabel, this.cs);

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                label,
                style: const TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.copy, size: 14),
              tooltip: 'Copy $copyLabel',
              visualDensity: VisualDensity.compact,
              padding: EdgeInsets.zero,
              onPressed: () {
                Clipboard.setData(ClipboardData(text: hex));
                ScaffoldMessenger.of(context)
                  ..hideCurrentSnackBar()
                  ..showSnackBar(
                    SnackBar(
                      content: Text('$copyLabel copied'),
                      duration: const Duration(seconds: 1),
                      behavior: SnackBarBehavior.floating,
                    ),
                  );
              },
            ),
          ],
        ),
        SelectableText(
          hex,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontSize: 10,
            height: 1.4,
          ),
        ),
        const SizedBox(height: 4),
      ],
    );
  }
}

class _DHArrow extends StatelessWidget {
  final String label;
  const _DHArrow(this.label);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          const Icon(Icons.arrow_downward, size: 14, color: Colors.grey),
          const SizedBox(width: 4),
          Expanded(
            child: Text(
              label,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 10,
                color: Colors.grey,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _DHCallBox extends StatelessWidget {
  final ColorScheme cs;
  final String call, resultHex, copyLabel;

  const _DHCallBox({
    required this.cs,
    required this.call,
    required this.resultHex,
    required this.copyLabel,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SelectableText(
          call,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontSize: 10.5,
            height: 1.5,
          ),
        ),
        _DHArrow('→ result'),
        _DHHexRow('= shared secret', resultHex, copyLabel, cs),
      ],
    );
  }
}

class _NetworkArrow extends StatelessWidget {
  final String label, left, right;
  final ColorScheme cs;

  const _NetworkArrow({
    required this.label,
    required this.left,
    required this.right,
    required this.cs,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Text(
          left,
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.bold,
            color: cs.primary,
          ),
        ),
        const SizedBox(width: 6),
        const Expanded(child: Divider(endIndent: 0, indent: 0, thickness: 1)),
        const Icon(Icons.arrow_forward, size: 14),
        const SizedBox(width: 6),
        Text(
          right,
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.bold,
            color: cs.primary,
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            label,
            style: TextStyle(fontSize: 10, color: cs.onSurfaceVariant),
          ),
        ),
      ],
    );
  }
}

// ─── Color metaphor page ──────────────────────────────────────────────────────

Color _keyColor(List<int> key) =>
    HSLColor.fromAHSL(1.0, (key[0] / 255) * 360, 0.65, 0.48).toColor();

class _ColorExchange {
  final Color laylaSecret, laylaPublic, yusufSecret, yusufPublic, shared;
  final String laylaPublicHex, yusufPublicHex, sharedHex;

  const _ColorExchange({
    required this.laylaSecret,
    required this.laylaPublic,
    required this.yusufSecret,
    required this.yusufPublic,
    required this.shared,
    required this.laylaPublicHex,
    required this.yusufPublicHex,
    required this.sharedHex,
  });
}

class ColorPage extends StatefulWidget {
  const ColorPage({super.key});

  @override
  State<ColorPage> createState() => _ColorPageState();
}

class _ColorPageState extends State<ColorPage> {
  _ColorExchange? _ex;

  void _run() {
    final aSec = SecretKey.generate();
    final aPub = Ed25519.generateX25519PublicKey(aSec);
    final bSec = SecretKey.generate();
    final bPub = Ed25519.generateX25519PublicKey(bSec);
    final shared = Ed25519.diffieHellman(aSec, bPub);
    final aSecBytes = aSec.toBytes();
    final bSecBytes = bSec.toBytes();
    final sharedBytes = shared.toBytes();
    try {
      setState(() {
        _ex = _ColorExchange(
          laylaSecret: _keyColor(aSecBytes),
          laylaPublic: _keyColor(aPub),
          yusufSecret: _keyColor(bSecBytes),
          yusufPublic: _keyColor(bPub),
          shared: _keyColor(sharedBytes),
          laylaPublicHex: EddsaUtils.hexFromBytes(aPub).substring(0, 16),
          yusufPublicHex: EddsaUtils.hexFromBytes(bPub).substring(0, 16),
          sharedHex: EddsaUtils.hexFromBytes(sharedBytes).substring(0, 16),
        );
      });
    } finally {
      aSec.dispose();
      bSec.dispose();
      shared.dispose();
      // ignore: deprecated_member_use
      EddsaUtils.zero(aSecBytes);
      // ignore: deprecated_member_use
      EddsaUtils.zero(bSecBytes);
      // ignore: deprecated_member_use
      EddsaUtils.zero(sharedBytes);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('How Diffie-Hellman works')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
        child: Column(
          children: [
            const Text(
              'Two people agree on a shared secret without ever sending it '
              'over the network. The color metaphor shows why: mixing paint '
              'is easy, but un-mixing it is practically impossible.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 14, height: 1.55),
            ),
            const SizedBox(height: 24),
            if (_ex == null) _buildIdle() else _buildResult(_ex!),
            const SizedBox(height: 28),
            FilledButton.icon(
              onPressed: _run,
              icon: const Icon(Icons.shuffle),
              label: Text(_ex == null ? 'Run key exchange' : 'Run again'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildIdle() {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(16),
      ),
      child: const Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          Column(
            children: [
              Icon(Icons.person, size: 40, color: Colors.grey),
              Text('Layla'),
            ],
          ),
          Icon(Icons.swap_horiz, size: 32, color: Colors.grey),
          Column(
            children: [
              Icon(Icons.person_2, size: 40, color: Colors.grey),
              Text('Yusuf'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildResult(_ColorExchange ex) {
    return Column(
      children: [
        _ColorStep(
          step: '1',
          label: 'Each picks a secret color',
          sublabel: 'Never shared with anyone',
          left: _Swatch(color: ex.laylaSecret, label: "Layla's\nsecret"),
          right: _Swatch(color: ex.yusufSecret, label: "Yusuf's\nsecret"),
          middle: const _EyeSlash(),
        ),
        const _StepArrow(),
        _ColorStep(
          step: '2',
          label: 'Mix with base → send publicly',
          sublabel: 'Eve can see these',
          left: _Swatch(
            color: ex.laylaPublic,
            label: "Layla's public\n${ex.laylaPublicHex}…",
          ),
          right: _Swatch(
            color: ex.yusufPublic,
            label: "Yusuf's public\n${ex.yusufPublicHex}…",
          ),
          middle: _EveBox(ac: ex.laylaPublic, bc: ex.yusufPublic),
        ),
        const _StepArrow(),
        _ColorStep(
          step: '3',
          label: "Mix peer's public with own secret",
          sublabel: 'Both arrive at the same color!',
          left: _Swatch(color: ex.shared, label: "Layla's\nshared secret"),
          right: _Swatch(color: ex.shared, label: "Yusuf's\nshared secret"),
          middle: _MatchBadge(hex: ex.sharedHex),
        ),
      ],
    );
  }
}

class _ColorStep extends StatelessWidget {
  final String step, label, sublabel;
  final Widget left, right, middle;
  const _ColorStep({
    required this.step,
    required this.label,
    required this.sublabel,
    required this.left,
    required this.right,
    required this.middle,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(12),
      margin: const EdgeInsets.only(bottom: 4),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 12,
                backgroundColor: cs.primary,
                child: Text(
                  step,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: cs.onPrimary,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      label,
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                      ),
                    ),
                    Text(
                      sublabel,
                      style: TextStyle(
                        fontSize: 11,
                        color: cs.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [left, Expanded(child: Center(child: middle)), right],
          ),
        ],
      ),
    );
  }
}

class _Swatch extends StatelessWidget {
  final Color color;
  final String label;
  const _Swatch({required this.color, required this.label});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Container(
          width: 56,
          height: 56,
          decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(12),
            boxShadow: [
              BoxShadow(
                color: color.withValues(alpha: 0.5),
                blurRadius: 8,
                offset: const Offset(0, 3),
              ),
            ],
          ),
        ),
        const SizedBox(height: 6),
        Text(
          label,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 10),
        ),
      ],
    );
  }
}

class _EyeSlash extends StatelessWidget {
  const _EyeSlash();
  @override
  Widget build(BuildContext context) => Column(
    children: [
      Icon(
        Icons.visibility_off,
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      ),
      const SizedBox(height: 4),
      const Text(
        "Eve\ncan't see",
        textAlign: TextAlign.center,
        style: TextStyle(fontSize: 10),
      ),
    ],
  );
}

class _EveBox extends StatelessWidget {
  final Color ac, bc;
  const _EveBox({required this.ac, required this.bc});
  @override
  Widget build(BuildContext context) => Column(
    children: [
      const Icon(Icons.remove_red_eye, color: Colors.orange, size: 18),
      const Text(
        'Eve sees:',
        style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold),
      ),
      const SizedBox(height: 4),
      Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 20,
            height: 20,
            decoration: BoxDecoration(
              color: ac,
              borderRadius: BorderRadius.circular(4),
            ),
          ),
          const SizedBox(width: 4),
          Container(
            width: 20,
            height: 20,
            decoration: BoxDecoration(
              color: bc,
              borderRadius: BorderRadius.circular(4),
            ),
          ),
        ],
      ),
      const SizedBox(height: 4),
      const Text(
        "but can't\ncrack it",
        textAlign: TextAlign.center,
        style: TextStyle(fontSize: 9, color: Colors.orange),
      ),
    ],
  );
}

class _MatchBadge extends StatelessWidget {
  final String hex;
  const _MatchBadge({required this.hex});
  @override
  Widget build(BuildContext context) => Column(
    children: [
      const Icon(Icons.check_circle, color: Colors.green, size: 22),
      const Text(
        'Match!',
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.bold,
          color: Colors.green,
        ),
      ),
      const SizedBox(height: 2),
      Text('$hex…', style: const TextStyle(fontSize: 8)),
    ],
  );
}

class _StepArrow extends StatelessWidget {
  const _StepArrow();
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 6),
    child: Icon(
      Icons.arrow_downward,
      color: Theme.of(context).colorScheme.onSurfaceVariant,
    ),
  );
}
