## 0.2.0

**Breaking changes** — secret inputs are now `SecretKey` instead of `Uint8List`.

* New `SecretKey` class: secrets held in `malloc`'d native memory, never on the
  Dart GC heap. `dispose()` zeros the buffer before freeing. A `NativeFinalizer`
  frees (but does not zero) on GC if `dispose` is forgotten.
* `Ed25519.derivePublicKey`, `signMessage`, `generateX25519PublicKey`,
  `scalarMultiply` now accept `SecretKey` for the secret argument.
* `Ed25519.diffieHellman` and `secretKeyToX25519` now return `SecretKey`
  (the shared secret and converted key are sensitive — caller must `dispose`).
* Secret bytes are passed to FFI via a direct native pointer — no arena copy
  of secret material, eliminating the free-without-zero gap.
* All `assert()` guards replaced with `ArgumentError` / `StateError` so
  validation fires in release mode.
* New `EddsaUtils.zero(Uint8List)` — best-effort heap wipe for the brief window
  when secrets pass through a `Uint8List` (e.g. after `SecretKey.fromBytes`).
* Added `topics:` to `pubspec.yaml` for pub.dev discoverability.
* README: new `SecretKey` usage section, updated API table, expanded security
  notes listing the 5 things users must still do themselves.

## 0.1.1

* Fixed pub.dev Example tab: replaced `example/example.dart` with
  `example/example.md` so the simple snippet takes priority over the
  full demo app (`example/lib/main.dart`).
* Updated installation version constraint in README to `^0.1.0`.

## 0.1.0

* Added `example/example.dart`: a minimal, copy-pastable snippet shown in the
  pub.dev Example tab, covering keypair generation, Ed25519 sign/verify, and
  X25519 Diffie-Hellman key exchange.

## 0.0.9

* Rewrote example app: step-by-step interactive demo covering key generation,
  Ed25519 signing, signature verification (including tamper detection), and
  X25519 Diffie-Hellman key exchange. All key and signature values are
  selectable and copyable.
* Added educational "color metaphor" page showing how DH key exchange works
  visually, accessible via the info button in the demo app.
* Added pub.dev version and pub points badges to README.
* Fixed installation snippet version constraint in README.

## 0.0.5

* Removed `EddsaUtils.bytesFromString` and `EddsaUtils.stringFromBytes` — not needed for cryptographic operations. Use `dart:convert`'s `utf8.encode`/`utf8.decode` for text encoding.

## 0.0.4

* Relicensed from GPL-3.0 to MIT.

## 0.0.3

* Fixed license.

## 0.0.2

* Improved README: added Diffie-Hellman concept explanation with ASCII diagram and KDF note.
* Replaced example app with a focused Diffie-Hellman demo for pub.dev Example tab.

## 0.0.1

* Initial release.
* Ed25519 digital signatures: key derivation, signing, and verification.
* X25519 Diffie-Hellman key exchange.
* Ed25519 ↔ X25519 key conversion for both public and secret keys.
* Cryptographically secure random key generation via `Random.secure()`.
* Native FFI implementation — no platform-channel overhead.
* Supports Android, iOS, macOS, Linux, and Windows.
