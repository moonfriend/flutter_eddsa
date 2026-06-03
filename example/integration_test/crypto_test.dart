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
      expect(
        toHex(pub),
        equals('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
      );
    });

    test('vector 2 — known secret yields known public key', () {
      final pub = Ed25519.derivePublicKey(
        hex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
      );
      expect(
        toHex(pub),
        equals('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
      );
    });
  });
}
