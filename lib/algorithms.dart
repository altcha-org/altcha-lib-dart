/// Algorithm selector for ALTCHA proof-of-work.
///
/// Import this file to access [adaptiveDeriveKey], which automatically
/// dispatches to the correct key-derivation function based on
/// [ChallengeParameters.algorithm].  Because [adaptiveDeriveKey] is a
/// top-level function it can be forwarded across Dart isolate boundaries.
library;

import 'src/algorithms/argon2id.dart' as argon2id;
import 'src/algorithms/pbkdf2.dart' as pbkdf2;
import 'src/algorithms/scrypt.dart' as scrypt;
import 'src/algorithms/sha.dart' as sha;
import 'src/types.dart';

export 'src/types.dart' show ChallengeParameters, DeriveKeyFunction, DeriveKeyResult;

/// Derives a key using the algorithm named in [parameters.algorithm].
///
/// Supported values (case-insensitive prefix match):
/// - `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`
/// - `SHA-256`, `SHA-384`, `SHA-512`
/// - `SCRYPT`
/// - `ARGON2ID`
///
/// Throws [UnsupportedError] for unknown algorithms.
Future<DeriveKeyResult> adaptiveDeriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final algorithm = parameters.algorithm.toUpperCase();
  if (algorithm.startsWith('PBKDF2')) {
    return pbkdf2.deriveKey(parameters, salt, password);
  } else if (algorithm == 'SHA-256' ||
      algorithm == 'SHA-384' ||
      algorithm == 'SHA-512') {
    return sha.deriveKey(parameters, salt, password);
  } else if (algorithm == 'SCRYPT') {
    return scrypt.deriveKey(parameters, salt, password);
  } else if (algorithm == 'ARGON2ID') {
    return argon2id.deriveKey(parameters, salt, password);
  }
  throw UnsupportedError('Unsupported algorithm: ${parameters.algorithm}');
}
