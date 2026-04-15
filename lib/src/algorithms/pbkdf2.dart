import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../types.dart';

/// PBKDF2 key derivation using [package:crypto] HMAC (faster than pointycastle).
Future<DeriveKeyResult> deriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final hash = _getHash(parameters.algorithm);
  final derivedKey = _pbkdf2(
    password: Uint8List.fromList(password),
    salt: Uint8List.fromList(salt),
    iterations: parameters.cost,
    keyLength: parameters.keyLength,
    hash: hash,
  );
  return DeriveKeyResult(derivedKey: derivedKey, parameters: {});
}

crypto.Hash _getHash(String algorithm) {
  switch (algorithm) {
    case 'PBKDF2/SHA-512':
      return crypto.sha512;
    case 'PBKDF2/SHA-384':
      return crypto.sha384;
    case 'PBKDF2/SHA-256':
    default:
      return crypto.sha256;
  }
}

Uint8List _pbkdf2({
  required Uint8List password,
  required Uint8List salt,
  required int iterations,
  required int keyLength,
  required crypto.Hash hash,
}) {
  // The HMAC key (password) is fixed for all iterations — create it once.
  final hmac = crypto.Hmac(hash, password);
  final digestLength = hmac.convert(const []).bytes.length;
  final numBlocks = (keyLength + digestLength - 1) ~/ digestLength;
  final output = Uint8List(numBlocks * digestLength);

  for (var blockNum = 1; blockNum <= numBlocks; blockNum++) {
    // U1 = HMAC(password, salt || INT(blockNum))
    final saltBlock = Uint8List(salt.length + 4)
      ..setAll(0, salt)
      ..[salt.length] = (blockNum >> 24) & 0xff
      ..[salt.length + 1] = (blockNum >> 16) & 0xff
      ..[salt.length + 2] = (blockNum >> 8) & 0xff
      ..[salt.length + 3] = blockNum & 0xff;

    // Avoid Uint8List.fromList copies in the inner loop — Digest.bytes is
    // already a List<int> and hmac.convert() accepts List<int> directly.
    var u = hmac.convert(saltBlock).bytes;
    final f = Uint8List.fromList(u); // accumulator = U1

    for (var iter = 1; iter < iterations; iter++) {
      u = hmac.convert(u).bytes;
      for (var i = 0; i < digestLength; i++) {
        f[i] ^= u[i];
      }
    }

    output.setAll((blockNum - 1) * digestLength, f);
  }

  return output.sublist(0, keyLength);
}
