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
