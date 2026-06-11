import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:flutter_eddsa/flutter_eddsa.dart';

Uint8List hex(String s) => EddsaUtils.bytesFromHex(s);
String toHex(Uint8List b) => EddsaUtils.hexFromBytes(b);

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // ─── SecretKey ────────────────────────────────────────────────────────────

  group('SecretKey', () {
    test('generate() produces a 32-byte key', () {
      final key = SecretKey.generate();
      expect(key.toBytes().length, equals(32));
      key.dispose();
    });

    test('fromBytes() round-trips a known value', () {
      final bytes = hex(
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
      );
      final key = SecretKey.fromBytes(bytes);
      expect(toHex(key.toBytes()), equals(toHex(bytes)));
      key.dispose();
    });

    test('fromBytes() rejects wrong length', () {
      expect(() => SecretKey.fromBytes(Uint8List(16)), throwsArgumentError);
      expect(() => SecretKey.fromBytes(Uint8List(0)), throwsArgumentError);
      expect(() => SecretKey.fromBytes(Uint8List(33)), throwsArgumentError);
    });

    test('toBytes() after dispose() throws StateError', () {
      final key = SecretKey.generate();
      key.dispose();
      expect(() => key.toBytes(), throwsStateError);
    });

    test('dispose() is idempotent', () {
      final key = SecretKey.generate();
      expect(() {
        key.dispose();
        key.dispose();
      }, returnsNormally);
    });

    test('generate() produces unique keys', () {
      final a = SecretKey.generate();
      final b = SecretKey.generate();
      expect(toHex(a.toBytes()), isNot(equals(toHex(b.toBytes()))));
      a.dispose();
      b.dispose();
    });
  });

  // ─── derivePublicKey ──────────────────────────────────────────────────────

  group('derivePublicKey', () {
    test('vector 1 — known secret yields known public key', () {
      final sk = SecretKey.fromBytes(
        hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
      );
      final pub = Ed25519.derivePublicKey(sk);
      sk.dispose();
      expect(
        toHex(pub),
        equals(
          'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        ),
      );
    });

    test('vector 2 — known secret yields known public key', () {
      final sk = SecretKey.fromBytes(
        hex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
      );
      final pub = Ed25519.derivePublicKey(sk);
      sk.dispose();
      expect(
        toHex(pub),
        equals(
          '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
        ),
      );
    });
  });

  // ─── signMessage ──────────────────────────────────────────────────────────

  group('signMessage', () {
    test('vector 1 — empty message produces known signature', () {
      final sk = SecretKey.fromBytes(
        hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
      );
      final sig = Ed25519.signMessage(
        sk,
        hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
        Uint8List(0),
      );
      sk.dispose();
      expect(
        toHex(sig),
        equals(
          'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        ),
      );
    });

    test('vector 2 — 1-byte message produces known signature', () {
      final sk = SecretKey.fromBytes(
        hex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
      );
      final sig = Ed25519.signMessage(
        sk,
        hex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
        Uint8List.fromList([0x72]),
      );
      sk.dispose();
      expect(
        toHex(sig),
        equals(
          '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
        ),
      );
    });
  });

  // ─── verifySignature ──────────────────────────────────────────────────────

  group('verifySignature', () {
    test('accepts valid signature — vector 1', () {
      expect(
        Ed25519.verifySignature(
          hex(
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
          ),
          hex(
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
          ),
          Uint8List(0),
        ),
        isTrue,
      );
    });

    test('accepts valid signature — vector 2', () {
      expect(
        Ed25519.verifySignature(
          hex(
            '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
          ),
          hex(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
          ),
          Uint8List.fromList([0x72]),
        ),
        isTrue,
      );
    });

    test('rejects tampered signature', () {
      expect(
        Ed25519.verifySignature(
          hex(
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100c',
          ),
          hex(
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
          ),
          Uint8List(0),
        ),
        isFalse,
      );
    });

    test('rejects signature for wrong message', () {
      expect(
        Ed25519.verifySignature(
          hex(
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
          ),
          hex(
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
          ),
          Uint8List.fromList([0x00]),
        ),
        isFalse,
      );
    });

    test('rejects signature for wrong public key', () {
      expect(
        Ed25519.verifySignature(
          hex(
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
          ),
          hex(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
          ),
          Uint8List(0),
        ),
        isFalse,
      );
    });

    test('throws ArgumentError for wrong-length signature', () {
      expect(
        () =>
            Ed25519.verifySignature(Uint8List(16), Uint8List(32), Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('throws ArgumentError for wrong-length public key', () {
      expect(
        () =>
            Ed25519.verifySignature(Uint8List(64), Uint8List(16), Uint8List(0)),
        throwsArgumentError,
      );
    });
  });

  // ─── generateX25519PublicKey ──────────────────────────────────────────────

  group('generateX25519PublicKey', () {
    test('equals scalarMultiply against standard base point', () {
      const basepoint =
          '0900000000000000000000000000000000000000000000000000000000000000';
      final scalar = SecretKey.fromBytes(
        hex('4a385b1ee872f194df74088c064de87e7d2a2baba277b6c2306cf087eef6fdca'),
      );
      expect(
        toHex(Ed25519.generateX25519PublicKey(scalar)),
        equals(toHex(Ed25519.scalarMultiply(scalar, hex(basepoint)))),
      );
      scalar.dispose();
    });
  });

  // ─── scalarMultiply ───────────────────────────────────────────────────────

  group('scalarMultiply', () {
    test('vector 1 — known scalar × point yields known result', () {
      final scalar = SecretKey.fromBytes(
        hex('4a385b1ee872f194df74088c064de87e7d2a2baba277b6c2306cf087eef6fdca'),
      );
      final result = Ed25519.scalarMultiply(
        scalar,
        hex('9c8bf8f7d339a64320747b20744ed1b54cb4770987dd623289e9d0bd269e503f'),
      );
      scalar.dispose();
      expect(
        toHex(result),
        equals(
          '4aa28982f83e1f06c3075236e27b0bdedafd0166c40ff3537ee90b4aa8a36253',
        ),
      );
    });
  });

  // ─── diffieHellman ────────────────────────────────────────────────────────

  group('diffieHellman', () {
    test('both parties compute the same shared secret', () {
      final aliceSec = SecretKey.fromBytes(
        hex('4a385b1ee872f194df74088c064de87e7d2a2baba277b6c2306cf087eef6fdca'),
      );
      final alicePub = Ed25519.generateX25519PublicKey(aliceSec);
      final bobSec = SecretKey.fromBytes(
        hex('9c8bf8f7d339a64320747b20744ed1b54cb4770987dd623289e9d0bd269e503f'),
      );
      final bobPub = Ed25519.generateX25519PublicKey(bobSec);

      final aliceShared = Ed25519.diffieHellman(aliceSec, bobPub);
      final bobShared = Ed25519.diffieHellman(bobSec, alicePub);

      expect(toHex(aliceShared.toBytes()), equals(toHex(bobShared.toBytes())));

      aliceSec.dispose();
      bobSec.dispose();
      aliceShared.dispose();
      bobShared.dispose();
    });

    test('throws ArgumentError for wrong-length peer key', () {
      final sk = SecretKey.generate();
      expect(
        () => Ed25519.diffieHellman(sk, Uint8List(16)),
        throwsArgumentError,
      );
      sk.dispose();
    });
  });

  // ─── key conversion ───────────────────────────────────────────────────────

  group('key conversion ed25519 → x25519', () {
    test(
      'vector 1 — generateX25519PublicKey(secretKeyToX25519(sk)) == publicKeyToX25519(pk)',
      () {
        final edsk = SecretKey.fromBytes(
          hex(
            '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
          ),
        );
        final edpk = Ed25519.derivePublicKey(edsk);
        final xsk = Ed25519.secretKeyToX25519(edsk);
        edsk.dispose();
        expect(
          toHex(Ed25519.generateX25519PublicKey(xsk)),
          equals(toHex(Ed25519.publicKeyToX25519(edpk))),
        );
        xsk.dispose();
      },
    );

    test(
      'vector 2 — generateX25519PublicKey(secretKeyToX25519(sk)) == publicKeyToX25519(pk)',
      () {
        final edsk = SecretKey.fromBytes(
          hex(
            '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
          ),
        );
        final edpk = Ed25519.derivePublicKey(edsk);
        final xsk = Ed25519.secretKeyToX25519(edsk);
        edsk.dispose();
        expect(
          toHex(Ed25519.generateX25519PublicKey(xsk)),
          equals(toHex(Ed25519.publicKeyToX25519(edpk))),
        );
        xsk.dispose();
      },
    );
  });

  // ─── EddsaUtils.zero ─────────────────────────────────────────────────────

  // ignore_for_file: deprecated_member_use
  group('EddsaUtils.zero', () {
    test('fills all bytes with zero', () {
      final buf = Uint8List.fromList([1, 2, 3, 4, 5]);
      EddsaUtils.zero(buf);
      expect(buf, equals(Uint8List(5)));
    });

    test('handles empty list', () {
      expect(() => EddsaUtils.zero(Uint8List(0)), returnsNormally);
    });
  });

  // ─── Property-based round-trip tests ─────────────────────────────────────

  group('property: sign → verify round-trip', () {
    test('100 random messages of varying length', () {
      final rng = Random.secure();
      for (int i = 0; i < 100; i++) {
        final sk = SecretKey.generate();
        final pk = Ed25519.derivePublicKey(sk);
        final msgLen = rng.nextInt(256);
        final msg = Uint8List.fromList(
          List.generate(msgLen, (_) => rng.nextInt(256)),
        );
        final sig = Ed25519.signMessage(sk, pk, msg);
        expect(
          Ed25519.verifySignature(sig, pk, msg),
          isTrue,
          reason: 'failed at iteration $i with $msgLen-byte message',
        );
        sk.dispose();
      }
    });

    test('tampered signature is always rejected', () {
      final rng = Random.secure();
      for (int i = 0; i < 20; i++) {
        final sk = SecretKey.generate();
        final pk = Ed25519.derivePublicKey(sk);
        final msg = Uint8List.fromList(
          List.generate(rng.nextInt(64), (_) => rng.nextInt(256)),
        );
        final sig = Ed25519.signMessage(sk, pk, msg);
        final tampered = Uint8List.fromList(sig);
        tampered[rng.nextInt(64)] ^= 0x01;
        expect(
          Ed25519.verifySignature(tampered, pk, msg),
          isFalse,
          reason: 'tampered sig accepted at iteration $i',
        );
        sk.dispose();
      }
    });
  });

  group('property: DH symmetry', () {
    test('50 random key pairs produce equal shared secrets', () {
      for (int i = 0; i < 50; i++) {
        final aSec = SecretKey.generate();
        final bSec = SecretKey.generate();
        final aPub = Ed25519.generateX25519PublicKey(aSec);
        final bPub = Ed25519.generateX25519PublicKey(bSec);
        final aShared = Ed25519.diffieHellman(aSec, bPub);
        final bShared = Ed25519.diffieHellman(bSec, aPub);
        expect(
          toHex(aShared.toBytes()),
          equals(toHex(bShared.toBytes())),
          reason: 'DH mismatch at iteration $i',
        );
        aSec.dispose();
        bSec.dispose();
        aShared.dispose();
        bShared.dispose();
      }
    });
  });
}
