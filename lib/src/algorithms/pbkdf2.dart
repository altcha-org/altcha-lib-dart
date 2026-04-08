import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../types.dart';

/// PBKDF2 key derivation.
Future<DeriveKeyResult> deriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final digest = _getDigest(parameters.algorithm);
  final derivedKey = _pbkdf2(
    password: Uint8List.fromList(password),
    salt: Uint8List.fromList(salt),
    iterations: parameters.cost,
    keyLength: parameters.keyLength,
    digest: digest,
  );
  return DeriveKeyResult(derivedKey: derivedKey, parameters: {});
}

Digest _getDigest(String algorithm) {
  switch (algorithm) {
    case 'PBKDF2/SHA-512':
      return SHA512Digest();
    case 'PBKDF2/SHA-384':
      return SHA384Digest();
    case 'PBKDF2/SHA-256':
    default:
      return SHA256Digest();
  }
}

Uint8List _pbkdf2({
  required Uint8List password,
  required Uint8List salt,
  required int iterations,
  required int keyLength,
  required Digest digest,
}) {
  final params = Pbkdf2Parameters(salt, iterations, keyLength);
  final gen = PBKDF2KeyDerivator(HMac(digest, digest.byteLength));
  gen.init(params);
  final key = Uint8List(keyLength);
  gen.deriveKey(password, 0, key, 0);
  return key;
}
