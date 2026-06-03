import 'dart:typed_data';

/// Ed25519 digital signatures and X25519 Diffie-Hellman key exchange.
///
/// All methods are static. Keys are 32 bytes; signatures are 64 bytes.
class Ed25519 {
  /// Derives the Ed25519 public key for [secret] (32 bytes).
  static Uint8List derivePublicKey(Uint8List secret) =>
      throw UnimplementedError();

  /// Signs [message] with [secret] and [publicKey].
  /// Returns a 64-byte signature.
  static Uint8List signMessage(
          Uint8List secret, Uint8List publicKey, Uint8List message) =>
      throw UnimplementedError();

  /// Returns `true` if [signature] is a valid Ed25519 signature
  /// over [message] by [publicKey].
  static bool verifySignature(
          Uint8List signature, Uint8List publicKey, Uint8List message) =>
      throw UnimplementedError();

  /// Computes the X25519 public key for [scalar] against the standard
  /// base point.
  static Uint8List generateX25519PublicKey(Uint8List scalar) =>
      throw UnimplementedError();

  /// Multiplies [scalar] by an arbitrary curve [point].
  static Uint8List scalarMultiply(Uint8List scalar, Uint8List point) =>
      throw UnimplementedError();

  /// Performs X25519 Diffie-Hellman key agreement between [secret] and
  /// [peerPublicKey].
  static Uint8List diffieHellman(Uint8List secret, Uint8List peerPublicKey) =>
      throw UnimplementedError();

  /// Converts an Ed25519 public key to its X25519 equivalent.
  static Uint8List publicKeyToX25519(Uint8List edPublicKey) =>
      throw UnimplementedError();

  /// Converts an Ed25519 secret key to its X25519 equivalent.
  static Uint8List secretKeyToX25519(Uint8List edSecretKey) =>
      throw UnimplementedError();
}

/// Encoding and conversion utilities.
class EddsaUtils {
  /// Decodes a lowercase hex string to bytes.
  static Uint8List bytesFromHex(String hex) {
    assert(hex.length.isEven);
    return Uint8List.fromList([
      for (int i = 0; i < hex.length; i += 2)
        int.parse(hex[i] + hex[i + 1], radix: 16),
    ]);
  }

  /// Encodes [bytes] as a lowercase hex string.
  static String hexFromBytes(Uint8List bytes) {
    final buf = StringBuffer();
    for (final byte in bytes) {
      buf.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return buf.toString();
  }

  /// Encodes [text] as UTF-8 bytes.
  static Uint8List bytesFromString(String text) {
    final out = Uint8List(text.length);
    for (int i = 0; i < text.length; i++) out[i] = text.codeUnitAt(i);
    return out;
  }

  /// Decodes UTF-8 [bytes] to a string.
  static String stringFromBytes(Uint8List bytes) =>
      String.fromCharCodes(bytes);
}
