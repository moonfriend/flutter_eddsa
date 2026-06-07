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

// ─── SecretKey ────────────────────────────────────────────────────────────────

/// An Ed25519 or X25519 secret key held in native (non-GC) memory.
///
/// Secret bytes live outside the Dart heap, preventing GC copies from leaving
/// unzeroed shadows in from-space. Call [dispose] when finished — it
/// overwrites the native buffer with zeros before freeing it.
///
/// A [NativeFinalizer] is attached as a safety net: if [dispose] is never
/// called the allocator will free the memory on the next GC cycle, but it
/// will **not** zero it first. Always call [dispose] explicitly.
///
/// **Avoid [toBytes] in production.** The returned [Uint8List] lives on the
/// Dart heap and is subject to GC copying. If you must extract bytes, zero
/// the result immediately with [EddsaUtils.zero].
class SecretKey implements Finalizable {
  static final _finalizer = NativeFinalizer(malloc.nativeFree);

  final Pointer<Uint8> _ptr;
  bool _disposed = false;

  SecretKey._internal(this._ptr) {
    _finalizer.attach(this, _ptr.cast(),
        externalSize: _Ffi.keyLength, detach: this);
  }

  /// Generates a cryptographically secure random [SecretKey].
  ///
  /// Random bytes are written directly into native memory and never touch the
  /// Dart heap.
  factory SecretKey.generate() {
    final ptr = malloc<Uint8>(_Ffi.keyLength);
    final rng = Random.secure();
    for (int i = 0; i < _Ffi.keyLength; i++) {
      ptr[i] = rng.nextInt(256);
    }
    return SecretKey._internal(ptr);
  }

  /// Creates a [SecretKey] by copying [bytes] into native memory.
  ///
  /// [bytes] must be exactly 32 bytes. After calling this, wipe [bytes] with
  /// [EddsaUtils.zero] to reduce the window the secret spends on the Dart heap.
  ///
  /// Throws [ArgumentError] if [bytes].length != 32.
  factory SecretKey.fromBytes(Uint8List bytes) {
    if (bytes.length != _Ffi.keyLength) {
      throw ArgumentError.value(
          bytes, 'bytes', 'must be exactly ${_Ffi.keyLength} bytes');
    }
    final ptr = malloc<Uint8>(_Ffi.keyLength);
    ptr.asTypedList(_Ffi.keyLength).setAll(0, bytes);
    return SecretKey._internal(ptr);
  }

  /// Copies the secret bytes out to a [Uint8List].
  ///
  /// Throws [StateError] if [dispose] has already been called.
  Uint8List toBytes() {
    _checkDisposed();
    return Uint8List.fromList(_ptr.asTypedList(_Ffi.keyLength));
  }

  /// Zeros the native buffer and releases the memory.
  ///
  /// Safe to call more than once — subsequent calls are no-ops.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _finalizer.detach(this);
    _ptr.asTypedList(_Ffi.keyLength).fillRange(0, _Ffi.keyLength, 0);
    malloc.free(_ptr);
  }

  Pointer<Uint8> get _nativePtr {
    _checkDisposed();
    return _ptr;
  }

  void _checkDisposed() {
    if (_disposed) throw StateError('SecretKey has been disposed');
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Ed25519 digital signatures and X25519 Diffie-Hellman key exchange.
///
/// All methods are static. Secret inputs are [SecretKey]; public keys and
/// signatures remain [Uint8List]. Keys are 32 bytes; signatures are 64 bytes.
class Ed25519 {
  /// Derives the Ed25519 public key for [secret].
  static Uint8List derivePublicKey(SecretKey secret) {
    return using((Arena arena) {
      final pubPtr = arena<Uint8>(_Ffi.keyLength);
      _Ffi.derivePublicKey(pubPtr, secret._nativePtr);
      return _read(pubPtr, _Ffi.keyLength);
    });
  }

  /// Signs [message] with [secret] and [publicKey].
  /// Returns a 64-byte signature.
  ///
  /// Throws [ArgumentError] if [publicKey].length != 32.
  static Uint8List signMessage(
      SecretKey secret, Uint8List publicKey, Uint8List message) {
    if (publicKey.length != _Ffi.keyLength) {
      throw ArgumentError.value(
          publicKey, 'publicKey', 'must be exactly ${_Ffi.keyLength} bytes');
    }
    return using((Arena arena) {
      final pubPtr = arena<Uint8>(_Ffi.keyLength);
      final msgPtr = arena<Uint8>(message.length + 1);
      final sigPtr = arena<Uint8>(_Ffi.signatureLength);
      _write(pubPtr, publicKey);
      _write(msgPtr, message);
      _Ffi.sign(sigPtr, secret._nativePtr, pubPtr, msgPtr, message.length);
      return _read(sigPtr, _Ffi.signatureLength);
    });
  }

  /// Returns `true` if [signature] is a valid Ed25519 signature over
  /// [message] by [publicKey].
  ///
  /// Throws [ArgumentError] if [signature].length != 64 or
  /// [publicKey].length != 32.
  static bool verifySignature(
      Uint8List signature, Uint8List publicKey, Uint8List message) {
    if (signature.length != _Ffi.signatureLength) {
      throw ArgumentError.value(
          signature, 'signature', 'must be exactly ${_Ffi.signatureLength} bytes');
    }
    if (publicKey.length != _Ffi.keyLength) {
      throw ArgumentError.value(
          publicKey, 'publicKey', 'must be exactly ${_Ffi.keyLength} bytes');
    }
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

  /// Computes the X25519 public key for [scalar] against the standard base point.
  static Uint8List generateX25519PublicKey(SecretKey scalar) {
    return using((Arena arena) {
      final outPtr = arena<Uint8>(_Ffi.keyLength);
      _Ffi.generateX25519PublicKey(outPtr, scalar._nativePtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Multiplies [scalar] by an arbitrary curve [point].
  ///
  /// Throws [ArgumentError] if [point].length != 32.
  static Uint8List scalarMultiply(SecretKey scalar, Uint8List point) {
    if (point.length != _Ffi.keyLength) {
      throw ArgumentError.value(
          point, 'point', 'must be exactly ${_Ffi.keyLength} bytes');
    }
    return using((Arena arena) {
      final pointPtr = arena<Uint8>(_Ffi.keyLength);
      final outPtr   = arena<Uint8>(_Ffi.keyLength);
      _write(pointPtr, point);
      _Ffi.scalarMultiply(outPtr, scalar._nativePtr, pointPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Performs X25519 Diffie-Hellman key agreement between [secret] and
  /// [peerPublicKey]. Returns the shared secret as a [SecretKey] — call
  /// [SecretKey.dispose] when done.
  ///
  /// Throws [ArgumentError] if [peerPublicKey].length != 32.
  static SecretKey diffieHellman(SecretKey secret, Uint8List peerPublicKey) {
    if (peerPublicKey.length != _Ffi.keyLength) {
      throw ArgumentError.value(
          peerPublicKey, 'peerPublicKey', 'must be exactly ${_Ffi.keyLength} bytes');
    }
    final outPtr = malloc<Uint8>(_Ffi.keyLength);
    try {
      using((Arena arena) {
        final peerPtr = arena<Uint8>(_Ffi.keyLength);
        _write(peerPtr, peerPublicKey);
        _Ffi.diffieHellman(outPtr, secret._nativePtr, peerPtr);
      });
      return SecretKey._internal(outPtr);
    } catch (_) {
      malloc.free(outPtr);
      rethrow;
    }
  }

  /// Converts an Ed25519 public key to its X25519 equivalent.
  ///
  /// Throws [ArgumentError] if [edPublicKey].length != 32.
  static Uint8List publicKeyToX25519(Uint8List edPublicKey) {
    if (edPublicKey.length != _Ffi.keyLength) {
      throw ArgumentError.value(
          edPublicKey, 'edPublicKey', 'must be exactly ${_Ffi.keyLength} bytes');
    }
    return using((Arena arena) {
      final inpPtr = arena<Uint8>(_Ffi.keyLength);
      final outPtr = arena<Uint8>(_Ffi.keyLength);
      _write(inpPtr, edPublicKey);
      _Ffi.publicKeyToX25519(outPtr, inpPtr);
      return _read(outPtr, _Ffi.keyLength);
    });
  }

  /// Converts an Ed25519 secret key to its X25519 equivalent. Returns the
  /// result as a [SecretKey] — call [SecretKey.dispose] when done.
  static SecretKey secretKeyToX25519(SecretKey edSecretKey) {
    final outPtr = malloc<Uint8>(_Ffi.keyLength);
    try {
      _Ffi.secretKeyToX25519(outPtr, edSecretKey._nativePtr);
      return SecretKey._internal(outPtr);
    } catch (_) {
      malloc.free(outPtr);
      rethrow;
    }
  }

  static Uint8List _read(Pointer<Uint8> ptr, int length) =>
      Uint8List.fromList(ptr.asTypedList(length));

  static void _write(Pointer<Uint8> ptr, Uint8List data) =>
      ptr.asTypedList(data.length).setAll(0, data);
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/// Encoding, conversion, and memory utilities.
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

  /// Generates a cryptographically secure random 32-byte value.
  static Uint8List generateRandom32() {
    final rng = Random.secure();
    return Uint8List.fromList(
        List.generate(_Ffi.keyLength, (_) => rng.nextInt(256)));
  }

  /// Best-effort wipe of [bytes] on the Dart heap.
  ///
  /// **Note:** Dart AOT may eliminate this call (no `volatile` equivalent).
  /// For deterministic zeroing keep secrets in a [SecretKey] instead.
  /// Use this to reduce — not eliminate — the exposure window when a secret
  /// has briefly passed through a [Uint8List] (e.g. after [SecretKey.fromBytes]).
  static void zero(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);
}
