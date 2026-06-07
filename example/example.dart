// ignore_for_file: avoid_print
import 'dart:convert';
import 'package:flutter_eddsa/flutter_eddsa.dart';

void main() {
  // ── Key generation ──────────────────────────────────────────────────────────
  final secret    = EddsaUtils.generateRandom32();
  final publicKey = Ed25519.derivePublicKey(secret);

  print('secret : ${EddsaUtils.hexFromBytes(secret)}');
  print('public : ${EddsaUtils.hexFromBytes(publicKey)}');

  // ── Sign & verify ───────────────────────────────────────────────────────────
  final message   = utf8.encode('Hello, Ed25519!');
  final signature = Ed25519.signMessage(secret, publicKey, message);
  final valid     = Ed25519.verifySignature(signature, publicKey, message);

  print('signature : ${EddsaUtils.hexFromBytes(signature)}');
  print('valid     : $valid'); // true

  // ── X25519 Diffie-Hellman ───────────────────────────────────────────────────
  final aliceSecret = EddsaUtils.generateRandom32();
  final alicePub    = Ed25519.generateX25519PublicKey(aliceSecret);

  final bobSecret = EddsaUtils.generateRandom32();
  final bobPub    = Ed25519.generateX25519PublicKey(bobSecret);

  final aliceShared = Ed25519.diffieHellman(aliceSecret, bobPub);
  final bobShared   = Ed25519.diffieHellman(bobSecret, alicePub);

  print('shared match: ${EddsaUtils.hexFromBytes(aliceShared) == EddsaUtils.hexFromBytes(bobShared)}'); // true
}
