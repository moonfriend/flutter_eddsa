# flutter_eddsa examples

## Key generation & Ed25519 sign / verify

```dart
import 'dart:convert';
import 'package:flutter_eddsa/flutter_eddsa.dart';

// Generate a random secret key and derive its public key
final secret    = EddsaUtils.generateRandom32();
final publicKey = Ed25519.derivePublicKey(secret);

// Sign a message
final message   = utf8.encode('Hello, Ed25519!');
final signature = Ed25519.signMessage(secret, publicKey, message);

// Verify the signature
final valid = Ed25519.verifySignature(signature, publicKey, message);
print(valid); // true
```

## X25519 Diffie-Hellman key exchange

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

// Each party generates a key pair
final aliceSecret = EddsaUtils.generateRandom32();
final alicePublic = Ed25519.generateX25519PublicKey(aliceSecret);

final bobSecret = EddsaUtils.generateRandom32();
final bobPublic = Ed25519.generateX25519PublicKey(bobSecret);

// Each side computes the shared secret independently
final aliceShared = Ed25519.diffieHellman(aliceSecret, bobPublic);
final bobShared   = Ed25519.diffieHellman(bobSecret,   alicePublic);

// Both arrive at the same value
assert(EddsaUtils.hexFromBytes(aliceShared) ==
       EddsaUtils.hexFromBytes(bobShared));
```

## Key conversion (Ed25519 → X25519)

```dart
import 'package:flutter_eddsa/flutter_eddsa.dart';

final xSecret = Ed25519.secretKeyToX25519(secret);
final xPublic = Ed25519.publicKeyToX25519(publicKey);
```
