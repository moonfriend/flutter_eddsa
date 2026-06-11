# flutter_eddsa examples

## Key generation & Ed25519 sign / verify

```dart
import 'dart:convert';
import 'package:flutter_eddsa/flutter_eddsa.dart';

// Generate a secret key in native memory (never touches the Dart GC heap)
final secret    = SecretKey.generate();
final publicKey = Ed25519.derivePublicKey(secret);

// Sign a message
final message   = utf8.encode('Hello, Ed25519!');
final signature = Ed25519.signMessage(secret, publicKey, message);

// Verify the signature
final valid = Ed25519.verifySignature(signature, publicKey, message);
print(valid); // true

// Always dispose when done — zeros native memory before freeing
secret.dispose();
```

## X25519 Diffie-Hellman key exchange

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

// Each party generates a key pair
final aliceSecret = SecretKey.generate();
final alicePublic = Ed25519.generateX25519PublicKey(aliceSecret);

final bobSecret = SecretKey.generate();
final bobPublic = Ed25519.generateX25519PublicKey(bobSecret);

// Each side independently computes the shared secret
// diffieHellman() returns a SecretKey — dispose it when done
final aliceShared = Ed25519.diffieHellman(aliceSecret, bobPublic);
final bobShared   = Ed25519.diffieHellman(bobSecret,   alicePublic);

assert(EddsaUtils.hexFromBytes(aliceShared.toBytes()) ==
       EddsaUtils.hexFromBytes(bobShared.toBytes()));

aliceSecret.dispose();
bobSecret.dispose();
aliceShared.dispose();
bobShared.dispose();
```

## Loading a saved key from storage

When a secret key must round-trip through a `Uint8List` (e.g. after reading
from Flutter Secure Storage), minimise the exposure window:

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

// bytes comes from secure storage / hex decode — lives on Dart heap briefly
final bytes  = EddsaUtils.bytesFromHex(savedHex);
final secret = SecretKey.fromBytes(bytes);
// ignore: deprecated_member_use
EddsaUtils.zero(bytes); // best-effort wipe — Dart AOT may eliminate this

// use secret ...
secret.dispose();
```

> **Note:** `EddsaUtils.zero()` is deprecated because Dart AOT may eliminate
> the zeroing as a dead store. It is still the best available option for
> wiping a `Uint8List` — use it, but do not rely on it as a hard guarantee.
> The `String` returned by storage APIs is immutable and cannot be zeroed.
> For ephemeral session keys prefer `SecretKey.generate()`.

## Key conversion (Ed25519 → X25519)

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

// secretKeyToX25519 returns a SecretKey — dispose it
final xSecret = Ed25519.secretKeyToX25519(secret);
final xPublic = Ed25519.publicKeyToX25519(publicKey);
xSecret.dispose();
```
