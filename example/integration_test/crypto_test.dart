import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:flutter_eddsa/flutter_eddsa.dart';

Uint8List hex(String s) => EddsaUtils.bytesFromHex(s);
String toHex(Uint8List b) => EddsaUtils.hexFromBytes(b);

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // ─── derivePublicKey ──────────────────────────────────────────────────────

  group('derivePublicKey', () {
    test('vector 1 — known secret yields known public key', () {
      final pub = Ed25519.derivePublicKey(
        hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
      );
      expect(toHex(pub),
          equals('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
    });

    test('vector 2 — known secret yields known public key', () {
      final pub = Ed25519.derivePublicKey(
        hex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
      );
      expect(toHex(pub),
          equals('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'));
    });
  });

  // ─── signMessage ──────────────────────────────────────────────────────────

  group('signMessage', () {
    test('vector 1 — empty message produces known signature', () {
      final sig = Ed25519.signMessage(
        hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
        hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
        Uint8List(0),
      );
      expect(toHex(sig), equals(
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
      ));
    });

    test('vector 2 — 1-byte message produces known signature', () {
      final sig = Ed25519.signMessage(
        hex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
        hex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
        Uint8List.fromList([0x72]),
      );
      expect(toHex(sig), equals(
        '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
      ));
    });
  });

  // ─── verifySignature ──────────────────────────────────────────────────────

  group('verifySignature', () {
    test('accepts valid signature — vector 1', () {
      expect(
        Ed25519.verifySignature(
          hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
          hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
          Uint8List(0),
        ),
        isTrue,
      );
    });

    test('accepts valid signature — vector 2', () {
      expect(
        Ed25519.verifySignature(
          hex('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
          hex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
          Uint8List.fromList([0x72]),
        ),
        isTrue,
      );
    });

    test('rejects tampered signature', () {
      expect(
        Ed25519.verifySignature(
          hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100c'),
          hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
          Uint8List(0),
        ),
        isFalse,
      );
    });

    test('rejects signature for wrong message', () {
      expect(
        Ed25519.verifySignature(
          hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
          hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
          Uint8List.fromList([0x00]),
        ),
        isFalse,
      );
    });

    test('rejects signature for wrong public key', () {
      expect(
        Ed25519.verifySignature(
          hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
          hex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
          Uint8List(0),
        ),
        isFalse,
      );
    });
  });

  // ─── generateX25519PublicKey ──────────────────────────────────────────────

  group('generateX25519PublicKey', () {
    test('equals scalarMultiply against standard base point', () {
      const basepoint = '0900000000000000000000000000000000000000000000000000000000000000';
      final scalar = hex('4a385b1ee872f194df74088c064de87e7d2a2baba277b6c2306cf087eef6fdca');
      expect(
        toHex(Ed25519.generateX25519PublicKey(scalar)),
        equals(toHex(Ed25519.scalarMultiply(scalar, hex(basepoint)))),
      );
    });
  });

  // ─── scalarMultiply ───────────────────────────────────────────────────────

  group('scalarMultiply', () {
    test('vector 1 — known scalar × point yields known result', () {
      final result = Ed25519.scalarMultiply(
        hex('4a385b1ee872f194df74088c064de87e7d2a2baba277b6c2306cf087eef6fdca'),
        hex('9c8bf8f7d339a64320747b20744ed1b54cb4770987dd623289e9d0bd269e503f'),
      );
      expect(toHex(result),
          equals('4aa28982f83e1f06c3075236e27b0bdedafd0166c40ff3537ee90b4aa8a36253'));
    });
  });

  // ─── diffieHellman ────────────────────────────────────────────────────────

  group('diffieHellman', () {
    test('both parties compute the same shared secret', () {
      final aliceSec = hex('4a385b1ee872f194df74088c064de87e7d2a2baba277b6c2306cf087eef6fdca');
      final alicePub = Ed25519.generateX25519PublicKey(aliceSec);
      final bobSec   = hex('9c8bf8f7d339a64320747b20744ed1b54cb4770987dd623289e9d0bd269e503f');
      final bobPub   = Ed25519.generateX25519PublicKey(bobSec);

      expect(
        toHex(Ed25519.diffieHellman(aliceSec, bobPub)),
        equals(toHex(Ed25519.diffieHellman(bobSec, alicePub))),
      );
    });
  });

  // ─── key conversion ───────────────────────────────────────────────────────

  group('key conversion ed25519 → x25519', () {
    test('vector 1 — generateX25519PublicKey(secretKeyToX25519(sk)) == publicKeyToX25519(pk)', () {
      final edsk = hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
      final edpk = Ed25519.derivePublicKey(edsk);
      expect(
        toHex(Ed25519.generateX25519PublicKey(Ed25519.secretKeyToX25519(edsk))),
        equals(toHex(Ed25519.publicKeyToX25519(edpk))),
      );
    });

    test('vector 2 — generateX25519PublicKey(secretKeyToX25519(sk)) == publicKeyToX25519(pk)', () {
      final edsk = hex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
      final edpk = Ed25519.derivePublicKey(edsk);
      expect(
        toHex(Ed25519.generateX25519PublicKey(Ed25519.secretKeyToX25519(edsk))),
        equals(toHex(Ed25519.publicKeyToX25519(edpk))),
      );
    });
  });
}
