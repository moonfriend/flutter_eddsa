import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

final DynamicLibrary _nativeLib = _loadLibrary();

DynamicLibrary _loadLibrary() {
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('libflutter_eddsa.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('flutter_eddsa.dll');
  }
  return DynamicLibrary.process();
}

// ─── FFI type pairs ───────────────────────────────────────────────────────────

typedef _CGenPub = Void Function(Pointer<Uint8> pub, Pointer<Uint8> sec);
typedef _GenPub   = void Function(Pointer<Uint8> pub, Pointer<Uint8> sec);

typedef _CSign = Void Function(
    Pointer<Uint8> sig, Pointer<Uint8> sec,
    Pointer<Uint8> pub, Pointer<Uint8> data, Size len);
typedef _Sign = void Function(
    Pointer<Uint8> sig, Pointer<Uint8> sec,
    Pointer<Uint8> pub, Pointer<Uint8> data, int len);

typedef _CVerify = Bool Function(
    Pointer<Uint8> sig, Pointer<Uint8> pub, Pointer<Uint8> data, Size len);
typedef _Verify = bool Function(
    Pointer<Uint8> sig, Pointer<Uint8> pub, Pointer<Uint8> data, int len);

typedef _CBasePoint = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> scalar);
typedef _BasePoint = void Function(
    Pointer<Uint8> out, Pointer<Uint8> scalar);

typedef _CScalarMul = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> scalar, Pointer<Uint8> point);
typedef _ScalarMul = void Function(
    Pointer<Uint8> out, Pointer<Uint8> scalar, Pointer<Uint8> point);

typedef _CDiffieHellman = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> sec, Pointer<Uint8> point);
typedef _DiffieHellman = void Function(
    Pointer<Uint8> out, Pointer<Uint8> sec, Pointer<Uint8> point);

typedef _CConvertPub = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> inp);
typedef _ConvertPub = void Function(
    Pointer<Uint8> out, Pointer<Uint8> inp);

typedef _CConvertSec = Void Function(
    Pointer<Uint8> out, Pointer<Uint8> inp);
typedef _ConvertSec = void Function(
    Pointer<Uint8> out, Pointer<Uint8> inp);

// ─── Native bindings ──────────────────────────────────────────────────────────

class _Ffi {
  static const int keyLength       = 32;
  static const int signatureLength = 64;

  static final _GenPub derivePublicKey = _nativeLib
      .lookup<NativeFunction<_CGenPub>>('ed25519_genpub')
      .asFunction<_GenPub>();

  static final _Sign sign = _nativeLib
      .lookup<NativeFunction<_CSign>>('ed25519_sign')
      .asFunction<_Sign>();

  static final _Verify verifySignature = _nativeLib
      .lookup<NativeFunction<_CVerify>>('ed25519_verify')
      .asFunction<_Verify>();

  static final _BasePoint generateX25519PublicKey = _nativeLib
      .lookup<NativeFunction<_CBasePoint>>('x25519_base')
      .asFunction<_BasePoint>();

  static final _ScalarMul scalarMultiply = _nativeLib
      .lookup<NativeFunction<_CScalarMul>>('x25519')
      .asFunction<_ScalarMul>();

  static final _DiffieHellman diffieHellman = _nativeLib
      .lookup<NativeFunction<_CDiffieHellman>>('DH')
      .asFunction<_DiffieHellman>();

  static final _ConvertPub publicKeyToX25519 = _nativeLib
      .lookup<NativeFunction<_CConvertPub>>('pk_ed25519_to_x25519')
      .asFunction<_ConvertPub>();

  static final _ConvertSec secretKeyToX25519 = _nativeLib
      .lookup<NativeFunction<_CConvertSec>>('sk_ed25519_to_x25519')
      .asFunction<_ConvertSec>();
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Ed25519 digital signatures and X25519 Diffie-Hellman key exchange.
///
/// All methods are static. Keys are 32 bytes; signatures are 64 bytes.
class Ed25519 {
  /// Derives the Ed25519 public key for [secret] (32 bytes).
  static Uint8List derivePublicKey(Uint8List secret) {
    assert(secret.length == _Ffi.keyLength);
    return using((Arena arena) {
      final secPtr = arena<Uint8>(_Ffi.keyLength);
      final pubPtr = arena<Uint8>(_Ffi.keyLength);
      _write(secPtr, secret);
      _Ffi.derivePublicKey(pubPtr, secPtr);
      return _read(pubPtr, _Ffi.keyLength);
    });
  }

  /// Signs [message] with [secret] and [publicKey].
  /// Returns a 64-byte signature.
  static Uint8List signMessage(
      Uint8List secret, Uint8List publicKey, Uint8List message) {
    assert(secret.length    == _Ffi.keyLength);
    assert(publicKey.length == _Ffi.keyLength);
    return using((Arena arena) {
      final secPtr = arena<Uint8>(_Ffi.keyLength);
      final pubPtr = arena<Uint8>(_Ffi.keyLength);
      final msgPtr = arena<Uint8>(message.length + 1);
      final sigPtr = arena<Uint8>(_Ffi.signatureLength);
      _write(secPtr, secret);
      _write(pubPtr, publicKey);
      _write(msgPtr, message);
      _Ffi.sign(sigPtr, secPtr, pubPtr, msgPtr, message.length);
      return _read(sigPtr, _Ffi.signatureLength);
    });
  }

  /// Returns `true` if [signature] is a valid Ed25519 signature over
  /// [message] by [publicKey].
  static bool verifySignature(
      Uint8List signature, Uint8List publicKey, Uint8List message) {
    assert(signature.length == _Ffi.signatureLength);
    assert(publicKey.length == _Ffi.keyLength);
    return using((Arena arena) {
      final sigPtr = arena<Uint8>(_Ffi.signatureLength);
      final pubPtr = arena<Uint8>(_Ffi.keyLength);
      final msgPtr = arena<Uint8>(message.length + 1);
      _write(sigPtr, signature);
      _write(pubPtr, publicKey);
      _write(msgPtr, message);
      return _Ffi.verifySignature(sigPtr, pubPtr, msgPtr, message.length);
    });
  }

  /// Computes the X25519 public key for [scalar] against the standard
  /// base point.
  static Uint8List generateX25519PublicKey(Uint8List scalar) {
    assert(scalar.length == _Ffi.keyLength);
    return using((Arena arena) {
      final scalarPtr = arena<Uint8>(_Ffi.keyLength);
      final outPtr    = arena<Uint8>(_Ffi.keyLength);
      _write(scalarPtr, scalar);
      _Ffi.generateX25519PublicKey(outPtr, scalarPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Multiplies [scalar] by an arbitrary curve [point].
  static Uint8List scalarMultiply(Uint8List scalar, Uint8List point) {
    assert(scalar.length == _Ffi.keyLength);
    assert(point.length  == _Ffi.keyLength);
    return using((Arena arena) {
      final scalarPtr = arena<Uint8>(_Ffi.keyLength);
      final pointPtr  = arena<Uint8>(_Ffi.keyLength);
      final outPtr    = arena<Uint8>(_Ffi.keyLength);
      _write(scalarPtr, scalar);
      _write(pointPtr, point);
      _Ffi.scalarMultiply(outPtr, scalarPtr, pointPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Performs X25519 Diffie-Hellman key agreement between [secret] and
  /// [peerPublicKey].
  static Uint8List diffieHellman(Uint8List secret, Uint8List peerPublicKey) {
    assert(secret.length        == _Ffi.keyLength);
    assert(peerPublicKey.length == _Ffi.keyLength);
    return using((Arena arena) {
      final secPtr  = arena<Uint8>(_Ffi.keyLength);
      final peerPtr = arena<Uint8>(_Ffi.keyLength);
      final outPtr  = arena<Uint8>(_Ffi.keyLength);
      _write(secPtr, secret);
      _write(peerPtr, peerPublicKey);
      _Ffi.diffieHellman(outPtr, secPtr, peerPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Converts an Ed25519 public key to its X25519 equivalent.
  static Uint8List publicKeyToX25519(Uint8List edPublicKey) {
    assert(edPublicKey.length == _Ffi.keyLength);
    return using((Arena arena) {
      final inpPtr = arena<Uint8>(_Ffi.keyLength);
      final outPtr = arena<Uint8>(_Ffi.keyLength);
      _write(inpPtr, edPublicKey);
      _Ffi.publicKeyToX25519(outPtr, inpPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Converts an Ed25519 secret key to its X25519 equivalent.
  static Uint8List secretKeyToX25519(Uint8List edSecretKey) {
    assert(edSecretKey.length == _Ffi.keyLength);
    return using((Arena arena) {
      final inpPtr = arena<Uint8>(_Ffi.keyLength);
      final outPtr = arena<Uint8>(_Ffi.keyLength);
      _write(inpPtr, edSecretKey);
      _Ffi.secretKeyToX25519(outPtr, inpPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  static Uint8List _read(Pointer<Uint8> ptr, int length) =>
      Uint8List.fromList(ptr.asTypedList(length));

  static void _write(Pointer<Uint8> ptr, Uint8List data) =>
      ptr.asTypedList(data.length).setAll(0, data);
}

// ─── Utilities ────────────────────────────────────────────────────────────────

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

  /// Generates a random 32-byte value.
  ///
  /// **Note:** uses a non-cryptographic RNG — for testing only.
  static Uint8List generateRandom32() {
    final rng = Random();
    return Uint8List.fromList(
        List.generate(_Ffi.keyLength, (_) => rng.nextInt(256)));
  }
}
