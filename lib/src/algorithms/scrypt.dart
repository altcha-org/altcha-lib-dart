import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../types.dart';

/// Scrypt key derivation.
Future<DeriveKeyResult> deriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final n = parameters.cost;
  final r = parameters.memoryCost ?? 8;
  final p = parameters.parallelism ?? 1;
  final keyLength = parameters.keyLength;

  final scrypt = Scrypt();
  scrypt.init(ScryptParameters(n, r, p, keyLength, Uint8List.fromList(salt)));
  final key = Uint8List(keyLength);
  scrypt.deriveKey(Uint8List.fromList(password), 0, key, 0);

  return DeriveKeyResult(derivedKey: key, parameters: {});
}
