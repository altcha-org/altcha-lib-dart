import 'dart:typed_data';

import 'package:argon2/argon2.dart';

import '../types.dart';

/// Argon2id key derivation.
///
/// Challenge parameters:
/// - `cost`       → iterations (time cost)
/// - `memoryCost` → memory in KiB (must be >= 8 * parallelism)
/// - `parallelism`→ lanes (degree of parallelism), defaults to 1
Future<DeriveKeyResult> deriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final params = Argon2Parameters(
    Argon2Parameters.ARGON2_id,
    Uint8List.fromList(salt),
    iterations: parameters.cost,
    memory: parameters.memoryCost ?? 65536,
    lanes: parameters.parallelism ?? 1,
    version: Argon2Parameters.ARGON2_VERSION_13,
  );

  final generator = Argon2BytesGenerator()..init(params);
  final result = Uint8List(parameters.keyLength);
  generator.generateBytes(Uint8List.fromList(password), result, 0, result.length);

  return DeriveKeyResult(derivedKey: result, parameters: {});
}
