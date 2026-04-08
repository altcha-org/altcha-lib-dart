import 'package:crypto/crypto.dart' as crypto;

import '../helpers.dart';
import '../types.dart';

/// SHA iterated key derivation (hash-chain).
Future<DeriveKeyResult> deriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final iterations = parameters.cost < 1 ? 1 : parameters.cost;
  List<int>? data;
  List<int>? derivedKey;

  for (var i = 0; i < iterations; i++) {
    if (i == 0) {
      data = concatBuffers(salt, password);
    } else {
      data = derivedKey!;
    }
    derivedKey = _hashDigest(parameters.algorithm, data);
  }

  return DeriveKeyResult(
    derivedKey: derivedKey!.sublist(0, parameters.keyLength),
    parameters: {},
  );
}

List<int> _hashDigest(String algorithm, List<int> data) {
  switch (algorithm.toUpperCase()) {
    case 'SHA-512':
      return crypto.sha512.convert(data).bytes;
    case 'SHA-384':
      return crypto.sha384.convert(data).bytes;
    case 'SHA-256':
    default:
      return crypto.sha256.convert(data).bytes;
  }
}
