import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_eddsa/flutter_eddsa.dart';

void main() {
  group('EddsaUtils.bytesFromHex', () {
    test('decodes known vector', () {
      expect(
        EddsaUtils.bytesFromHex('deadbeef'),
        equals(Uint8List.fromList([0xde, 0xad, 0xbe, 0xef])),
      );
    });

    test('decodes all-zeros', () {
      expect(EddsaUtils.bytesFromHex('0000'), equals(Uint8List(2)));
    });

    test('decodes empty string to empty list', () {
      expect(EddsaUtils.bytesFromHex(''), equals(Uint8List(0)));
    });

    test('decodes single byte', () {
      expect(EddsaUtils.bytesFromHex('ff'), equals(Uint8List.fromList([0xff])));
    });

    test('throws ArgumentError on odd-length input', () {
      expect(() => EddsaUtils.bytesFromHex('abc'), throwsArgumentError);
      expect(() => EddsaUtils.bytesFromHex('f'), throwsArgumentError);
    });
  });

  group('EddsaUtils.hexFromBytes', () {
    test('encodes known vector', () {
      expect(
        EddsaUtils.hexFromBytes(Uint8List.fromList([0xde, 0xad, 0xbe, 0xef])),
        equals('deadbeef'),
      );
    });

    test('pads single-digit bytes with leading zero', () {
      expect(
        EddsaUtils.hexFromBytes(Uint8List.fromList([0x00, 0x0f, 0x10])),
        equals('000f10'),
      );
    });

    test('encodes all-zeros', () {
      expect(EddsaUtils.hexFromBytes(Uint8List(3)), equals('000000'));
    });

    test('encodes empty list to empty string', () {
      expect(EddsaUtils.hexFromBytes(Uint8List(0)), equals(''));
    });

    test('round-trips with bytesFromHex', () {
      const hex =
          '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
      expect(
        EddsaUtils.hexFromBytes(EddsaUtils.bytesFromHex(hex)),
        equals(hex),
      );
    });
  });

  // ignore_for_file: deprecated_member_use_from_same_package
  group('EddsaUtils.zero', () {
    test('fills all bytes with zero', () {
      final buf = Uint8List.fromList([1, 2, 3, 4, 5]);
      EddsaUtils.zero(buf);
      expect(buf, equals(Uint8List(5)));
    });

    test('handles empty list without throwing', () {
      expect(() => EddsaUtils.zero(Uint8List(0)), returnsNormally);
    });

    test('zeroes 32-byte buffer', () {
      final buf = Uint8List.fromList(List.generate(32, (i) => i + 1));
      EddsaUtils.zero(buf);
      expect(buf, equals(Uint8List(32)));
    });
  });

  group('EddsaUtils.generateRandom32', () {
    test('returns exactly 32 bytes', () {
      expect(EddsaUtils.generateRandom32().length, equals(32));
    });

    test('returns distinct values on consecutive calls', () {
      final a = EddsaUtils.hexFromBytes(EddsaUtils.generateRandom32());
      final b = EddsaUtils.hexFromBytes(EddsaUtils.generateRandom32());
      expect(a, isNot(equals(b)));
    });
  });
}
