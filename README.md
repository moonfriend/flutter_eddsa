# flutter_eddsa

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
  flutter_eddsa: ^0.0.1
```

```sh
flutter pub get
```

---

## Usage

### Generate a key pair

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

// Generate a random 32-byte secret key
final secret = EddsaUtils.generateRandom32();

// Derive the corresponding Ed25519 public key
final publicKey = Ed25519.derivePublicKey(secret);
```

### Sign a message

```dart
final message   = EddsaUtils.bytesFromString('Hello, flutter_eddsa!');
final signature = Ed25519.signMessage(secret, publicKey, message);
```

### Verify a signature

```dart
final isValid = Ed25519.verifySignature(signature, publicKey, message);
print(isValid); // true
```

### X25519 Diffie-Hellman key exchange

```dart
// Alice
final aliceSecret = EddsaUtils.generateRandom32();
final alicePublic  = Ed25519.generateX25519PublicKey(aliceSecret);

// Bob
final bobSecret = EddsaUtils.generateRandom32();
final bobPublic  = Ed25519.generateX25519PublicKey(bobSecret);

// Both sides arrive at the same shared secret
final aliceShared = Ed25519.diffieHellman(aliceSecret, bobPublic);
final bobShared   = Ed25519.diffieHellman(bobSecret,   alicePublic);

assert(EddsaUtils.hexFromBytes(aliceShared) ==
       EddsaUtils.hexFromBytes(bobShared));
```

### Convert an Ed25519 key pair to X25519

```dart
final xSecret = Ed25519.secretKeyToX25519(secret);
final xPublic  = Ed25519.publicKeyToX25519(publicKey);
```

---

## API reference

### `Ed25519`

All methods are static. Keys are 32 bytes; signatures are 64 bytes.

| Method | Input | Output | Description |
|--------|-------|--------|-------------|
| `derivePublicKey(secret)` | 32 B secret | 32 B public key | Derives an Ed25519 public key |
| `signMessage(secret, publicKey, message)` | keys + arbitrary message | 64 B signature | Signs a message |
| `verifySignature(signature, publicKey, message)` | 64 B sig + key + message | `bool` | Verifies a signature |
| `generateX25519PublicKey(scalar)` | 32 B scalar | 32 B public key | Scalar × base point (X25519 key generation) |
| `scalarMultiply(scalar, point)` | 32 B scalar + 32 B point | 32 B result | Raw X25519 scalar multiplication |
| `diffieHellman(secret, peerPublicKey)` | own secret + peer public | 32 B shared secret | X25519 key agreement |
| `publicKeyToX25519(edPublicKey)` | 32 B Ed25519 public key | 32 B X25519 public key | Key format conversion |
| `secretKeyToX25519(edSecretKey)` | 32 B Ed25519 secret key | 32 B X25519 secret key | Key format conversion |

### `EddsaUtils`

| Method | Description |
|--------|-------------|
| `generateRandom32()` | Cryptographically secure 32-byte random value |
| `bytesFromHex(hex)` | Decode a lowercase hex string to `Uint8List` |
| `hexFromBytes(bytes)` | Encode `Uint8List` as a lowercase hex string |
| `bytesFromString(text)` | Encode a UTF-8 string as bytes |
| `stringFromBytes(bytes)` | Decode bytes to a UTF-8 string |

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

- Keys and signatures are passed as raw `Uint8List` — never log or persist secret keys.
- `generateRandom32()` uses Dart's `Random.secure()`, which draws from the OS entropy pool.
- This plugin provides **primitives only**. For a complete secure channel you will also need
  a symmetric cipher and message authentication (e.g. AES-GCM or ChaCha20-Poly1305).

---

## License

This plugin is licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).

The bundled C cryptographic library (`src/crypto/`) is in the **public domain**
(original work by Philipp Lay).
