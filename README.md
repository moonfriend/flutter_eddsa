# flutter_eddsa

[![pub package](https://img.shields.io/pub/v/flutter_eddsa.svg)](https://pub.dev/packages/flutter_eddsa)
[![pub points](https://img.shields.io/pub/points/flutter_eddsa)](https://pub.dev/packages/flutter_eddsa/score)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Elliptic-curve cryptography for Flutter** — Ed25519 digital signatures and X25519 Diffie-Hellman key exchange, delivered through a direct native FFI bridge with no platform-channel overhead.

The same algorithms that secure **Signal, WireGuard, OpenSSH, and TLS 1.3** — now available as a clean, cross-platform Flutter plugin.

---

## Why Curve25519?

Curve25519 is the modern standard for high-speed, high-security elliptic-curve cryptography:

- **Ed25519** — deterministic digital signatures. Fast to sign, fast to verify, no random number generator required at signing time, and immune to the class of fault attacks that affect ECDSA.
- **X25519** — Diffie-Hellman key agreement. Two parties can establish a shared secret over an untrusted channel without ever transmitting a private key.

Both primitives are built on the same underlying curve, which means an Ed25519 key pair can be converted to X25519 format — useful when a single long-term key pair needs to serve both signing and key-exchange roles.

---

## Features

- **Ed25519** public key derivation, signing, and verification
- **X25519** Diffie-Hellman key agreement
- **Key conversion** — Ed25519 ↔ X25519 for both public and secret keys
- Pure native performance via `dart:ffi` — no method channels, no serialisation overhead
- Cryptographically secure random key generation
- Android · iOS · Linux · macOS · Windows

---

## Installation

```yaml
dependencies:
  flutter_eddsa: ^0.2.0
```

```sh
flutter pub get
```

---

## Usage

### Generate a key pair

Secrets are held in `SecretKey` — a native-memory wrapper that zeros its
buffer on `dispose()` and never touches the Dart GC heap.

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

// Generate a secret key directly in native memory
final secret    = SecretKey.generate();
final publicKey = Ed25519.derivePublicKey(secret);
```

### Sign a message

```dart
import 'dart:convert';

final message   = utf8.encode('Hello, flutter_eddsa!');
final signature = Ed25519.signMessage(secret, publicKey, message);
```

### Verify a signature

```dart
final isValid = Ed25519.verifySignature(signature, publicKey, message);
print(isValid); // true
```

### Dispose when done

Always call `dispose()` on every `SecretKey` when you no longer need it.
This zeros the native buffer before freeing — the essential step for
memory-dump resistance.

```dart
secret.dispose(); // zeros + frees native memory
```

### X25519 Diffie-Hellman key exchange

Diffie-Hellman lets two parties establish a **shared secret over a public channel**
without ever transmitting a private key. The idea: each party combines their own
secret with the other party's public key, and the mathematics of the elliptic curve
guarantees both arrive at the same result.

```
Alice                              Bob
─────                              ───
aliceSecret (private)              bobSecret (private)
alicePublic = secret × G           bobPublic  = secret × G
         ──── exchange public keys ────▶
sharedSecret = aliceSecret × bobPublic
                                   sharedSecret = bobSecret × alicePublic
         (same value on both sides — proven by the associativity of scalar multiplication)
```

In code:

```dart
// Each party generates a key pair
final aliceSecret = SecretKey.generate();
final alicePublic = Ed25519.generateX25519PublicKey(aliceSecret);

final bobSecret = SecretKey.generate();
final bobPublic = Ed25519.generateX25519PublicKey(bobSecret);

// They exchange public keys (safe to send over untrusted network)
// Each computes the shared secret independently
// diffieHellman() returns a SecretKey — the shared secret is sensitive
final aliceShared = Ed25519.diffieHellman(aliceSecret, bobPublic);
final bobShared   = Ed25519.diffieHellman(bobSecret,   alicePublic);

// Both arrive at the same 32-byte value
assert(EddsaUtils.hexFromBytes(aliceShared.toBytes()) ==
       EddsaUtils.hexFromBytes(bobShared.toBytes()));

// Dispose all secrets when done
aliceSecret.dispose();
bobSecret.dispose();
aliceShared.dispose();
bobShared.dispose();

// Use the shared secret to derive an encryption key (e.g. with HKDF or SHA-256)
```

The shared secret is typically passed through a key-derivation function (KDF) before
use as a symmetric encryption key.

### Loading a key from storage

When a secret must briefly pass through a `Uint8List` (e.g. reading from
Flutter Secure Storage), minimise the exposure window:

```dart
final bytes  = EddsaUtils.bytesFromHex(savedHex);
final secret = SecretKey.fromBytes(bytes);
EddsaUtils.zero(bytes); // best-effort wipe of the Dart-heap copy
// use secret ...
secret.dispose();
```

> **Note:** The `String` from storage APIs is immutable and cannot be zeroed.
> For ephemeral session keys, always prefer `SecretKey.generate()`.

### Convert an Ed25519 key pair to X25519

```dart
// secretKeyToX25519 returns a SecretKey — dispose it when done
final xSecret = Ed25519.secretKeyToX25519(secret);
final xPublic = Ed25519.publicKeyToX25519(publicKey);
xSecret.dispose();
```

---

## API reference

### `SecretKey`

Holds a 32-byte secret in native (non-GC) memory.

| Member | Description |
|--------|-------------|
| `SecretKey.generate()` | Random key written directly into native memory |
| `SecretKey.fromBytes(Uint8List)` | Copy bytes in; throws `ArgumentError` if length ≠ 32 |
| `toBytes()` → `Uint8List` | Copy bytes out to Dart heap; throws `StateError` after dispose |
| `dispose()` | Zero + free native memory; idempotent |

### `Ed25519`

All methods are static. Secret inputs are `SecretKey`; public keys and
signatures remain `Uint8List`. Keys are 32 bytes; signatures are 64 bytes.
All methods throw `ArgumentError` if a `Uint8List` argument has the wrong length.

| Method | Secret input | Output | Description |
|--------|-------------|--------|-------------|
| `derivePublicKey(secret)` | `SecretKey` | `Uint8List` (32 B) | Derives an Ed25519 public key |
| `signMessage(secret, publicKey, message)` | `SecretKey` | `Uint8List` (64 B) | Signs a message |
| `verifySignature(signature, publicKey, message)` | — | `bool` | Verifies a signature |
| `generateX25519PublicKey(scalar)` | `SecretKey` | `Uint8List` (32 B) | Scalar × base point |
| `scalarMultiply(scalar, point)` | `SecretKey` | `Uint8List` (32 B) | Raw X25519 scalar multiplication |
| `diffieHellman(secret, peerPublicKey)` | `SecretKey` | **`SecretKey`** | X25519 key agreement — dispose result |
| `publicKeyToX25519(edPublicKey)` | — | `Uint8List` (32 B) | Ed25519 → X25519 public key |
| `secretKeyToX25519(edSecretKey)` | `SecretKey` | **`SecretKey`** | Ed25519 → X25519 secret key — dispose result |

### `EddsaUtils`

| Method | Description |
|--------|-------------|
| `generateRandom32()` | Cryptographically secure 32-byte `Uint8List` (use `SecretKey.generate()` for secrets) |
| `bytesFromHex(hex)` | Decode a lowercase hex string to `Uint8List` |
| `hexFromBytes(bytes)` | Encode `Uint8List` as a lowercase hex string |
| `zero(bytes)` | Best-effort heap wipe — see security notes |

---

## Platform support

| Platform | Status |
|----------|--------|
| Android  | ✅ |
| iOS      | ✅ |
| macOS    | ✅ |
| Linux    | ✅ |
| Windows  | ✅ |
| Web      | ❌ (not yet supported) |

---

## Native cryptographic core

The cryptographic implementation is provided by
[libeddsa](https://github.com/phlay/libeddsa) — a compact, public-domain C library
by **Philipp Lay** with the following properties:

- Written in portable C99
- Constant-time scalar multiplication (timing-attack resistant)
- Stack-cleaning after secret key operations
- No external dependencies
- Under 90 KB compiled

The C source is vendored directly into `src/crypto/` and compiled as part of the
Flutter build for each platform — no pre-built binaries, no external downloads.

---

## Security notes

### Memory safety — what `SecretKey` protects against

Dart's GC is a **copying collector**: when promoting objects between heap
generations it copies bytes to a new address, leaving the original bytes
unzeroed. Dart also has no `volatile` equivalent, so a `fillRange(0)` on a
`Uint8List` can be eliminated by the AOT compiler as a dead store.

`SecretKey` sidesteps both issues by keeping secret bytes in `malloc`'d
native memory that the GC never touches. `dispose()` zeros the buffer
before freeing it, matching what the underlying C library (`libeddsa`) does
with `burn()` / `burnstack()` for on-stack secrets.

### What you still need to do

Even with `SecretKey`, there are gaps you must manage yourself:

1. **Call `dispose()` explicitly.** The `NativeFinalizer` will free the
   memory on GC if you forget, but it will **not** zero it first.

2. **After `SecretKey.fromBytes(bytes)`, call `EddsaUtils.zero(bytes)`.**
   This is a best-effort wipe of the `Uint8List` that briefly held the
   secret on the Dart heap. AOT may eliminate it, but it is still worth
   doing to reduce the exposure window.

3. **You cannot zero a `String`.** Storage APIs (Flutter Secure Storage,
   SharedPreferences) return Dart `String` values, which are immutable and
   interned. The hex or base64 string will remain in memory until the GC
   collects it. This is a fundamental platform limitation — mitigate it by
   using hardware-backed storage (Keychain on iOS, Keystore on Android) so
   the raw key material is never returned to Dart at all where possible.

4. **`toBytes()` places the secret on the Dart heap.** Only call it when
   you have no alternative, and zero the result immediately with
   `EddsaUtils.zero(result)` after use.

5. **This plugin provides primitives only.** For a complete secure channel
   you also need a symmetric cipher and message authentication
   (e.g. AES-GCM or ChaCha20-Poly1305).

- `SecretKey.generate()` uses Dart's `Random.secure()`, which draws from the OS entropy pool.
- Never log or persist a `SecretKey`'s bytes; if you must serialise a key, use hardware-backed secure storage.

---

## License

This plugin is licensed under the **MIT License** — see [LICENSE](LICENSE).

The bundled C cryptographic library (`src/crypto/`) is in the **public domain**
(original work by Philipp Lay).
