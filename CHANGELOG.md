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
