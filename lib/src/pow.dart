import 'dart:async';
import 'dart:convert';

import 'helpers.dart';
import 'password_buffer.dart';
import 'types.dart';

/// Creates a new proof-of-work challenge.
Future<Challenge> createChallenge({
  required String algorithm,
  required int cost,
  required DeriveKeyFunction deriveKey,
  int? counter,
  CounterMode counterMode = CounterMode.uint32,
  Map<String, Object?>? data,
  Object? expiresAt, // int (unix seconds) or DateTime
  HmacAlgorithm hmacAlgorithm = HmacAlgorithm.sha256,
  String? hmacKeySignatureSecret,
  String? hmacSignatureSecret,
  int keyLength = 32,
  String keyPrefix = '00',
  int? keyPrefixLength,
  int? memoryCost,
  int? parallelism,
}) async {
  final kPrefixLen = keyPrefixLength ?? keyLength ~/ 2;

  int? expiresAtSeconds;
  if (expiresAt is DateTime) {
    expiresAtSeconds = expiresAt.millisecondsSinceEpoch ~/ 1000;
  } else if (expiresAt is int) {
    expiresAtSeconds = expiresAt;
  }

  var parameters = ChallengeParameters(
    algorithm: algorithm,
    nonce: bufferToHex(randomBytes(16)),
    salt: bufferToHex(randomBytes(16)),
    cost: cost,
    keyLength: keyLength,
    keyPrefix: keyPrefix,
    memoryCost: memoryCost,
    parallelism: parallelism,
    expiresAt: expiresAtSeconds,
    data: data,
  );

  DeriveKeyResult? deriveKeyResult;
  if (counter != null) {
    final nonceBuf = hexToBuffer(parameters.nonce);
    final saltBuf = hexToBuffer(parameters.salt);
    final password =
        PasswordBuffer(nonceBuf, mode: counterMode == CounterMode.string ? 'string' : 'uint32')
            .setCounter(counter);
    deriveKeyResult = await deriveKey(parameters, saltBuf, password);
    if (deriveKeyResult.parameters != null) {
      // Merge extra parameters returned by deriveKey (e.g. updated memoryCost).
      final p = deriveKeyResult.parameters!;
      parameters = ChallengeParameters(
        algorithm: p['algorithm'] as String? ?? parameters.algorithm,
        nonce: parameters.nonce,
        salt: parameters.salt,
        cost: p['cost'] as int? ?? parameters.cost,
        keyLength: p['keyLength'] as int? ?? parameters.keyLength,
        keyPrefix: parameters.keyPrefix,
        memoryCost: p['memoryCost'] as int? ?? parameters.memoryCost,
        parallelism: p['parallelism'] as int? ?? parameters.parallelism,
        expiresAt: parameters.expiresAt,
        data: parameters.data,
      );
    }
    parameters = parameters.copyWith(
      keyPrefix: bufferToHex(deriveKeyResult.derivedKey.sublist(0, kPrefixLen)),
    );
  }

  if (hmacSignatureSecret == null) {
    return Challenge(parameters: parameters);
  }

  return _signChallenge(
    hmacAlgorithm,
    parameters,
    deriveKeyResult?.derivedKey,
    hmacSignatureSecret,
    hmacKeySignatureSecret,
  );
}

/// Signs challenge parameters with HMAC and returns a [Challenge] with a signature.
Future<Challenge> _signChallenge(
  HmacAlgorithm algorithm,
  ChallengeParameters parameters,
  List<int>? derivedKey,
  String hmacSignatureSecret,
  String? hmacKeySignatureSecret,
) async {
  if (derivedKey != null && hmacKeySignatureSecret != null) {
    parameters = parameters.copyWith(
      keySignature: bufferToHex(
        hmacSign(algorithm, derivedKey, hmacKeySignatureSecret),
      ),
    );
  }
  final sortedJson = parameters.toSortedJson();
  final signature = bufferToHex(
    hmacSignString(algorithm, jsonEncode(sortedJson), hmacSignatureSecret),
  );
  return Challenge(parameters: parameters, signature: signature);
}

/// Public wrapper for signing, exposed for testing.
Future<Challenge> signChallenge(
  HmacAlgorithm algorithm,
  ChallengeParameters parameters,
  List<int>? derivedKey,
  String hmacSignatureSecret,
  String? hmacKeySignatureSecret,
) =>
    _signChallenge(
        algorithm, parameters, derivedKey, hmacSignatureSecret, hmacKeySignatureSecret);

/// Solves a challenge by iterating counter values until the derived key
/// starts with [Challenge.parameters.keyPrefix].
///
/// Returns [null] on timeout or abort.
Future<Solution?> solveChallenge({
  required Challenge challenge,
  required DeriveKeyFunction deriveKey,
  CounterMode counterMode = CounterMode.uint32,
  int counterStart = 0,
  int counterStep = 1,
  Duration timeout = const Duration(seconds: 90),
  Stream<void>? abortSignal,
}) async {
  final params = challenge.parameters;
  final nonceBuf = hexToBuffer(params.nonce);
  final saltBuf = hexToBuffer(params.salt);

  // Pre-parse prefix to bytes if it has even length for fast comparison.
  final List<int>? keyPrefixBuf =
      params.keyPrefix.length % 2 == 0 ? hexToBuffer(params.keyPrefix) : null;

  final passwordBuf = PasswordBuffer(
    nonceBuf,
    mode: counterMode == CounterMode.string ? 'string' : 'uint32',
  );

  final start = DateTime.now();
  var counter = counterStart;
  var iteration = 0;
  bool aborted = false;

  StreamSubscription<void>? abortSub;
  if (abortSignal != null) {
    abortSub = abortSignal.listen((_) => aborted = true);
  }

  try {
    while (true) {
      // Every 10 iterations: check abort/timeout and yield to the event loop.
      if (iteration % 10 == 0) {
        if (aborted) return null;
        if (DateTime.now().difference(start) > timeout) return null;
        await Future<void>.delayed(Duration.zero);
      }

      final result =
          await deriveKey(params, saltBuf, passwordBuf.setCounter(counter));
      final derivedKey = result.derivedKey;

      final matches = keyPrefixBuf != null
          ? bufferStartsWith(derivedKey, keyPrefixBuf)
          : bufferToHex(derivedKey).startsWith(params.keyPrefix);

      if (matches) {
        return Solution(
          counter: counter,
          derivedKey: bufferToHex(derivedKey),
          time: timeDuration(start),
        );
      }
      counter += counterStep;
      iteration++;
    }
  } finally {
    await abortSub?.cancel();
  }
}

/// Verifies a submitted [solution] against a [challenge].
Future<VerifySolutionResult> verifySolution({
  required Challenge challenge,
  required Solution solution,
  required DeriveKeyFunction deriveKey,
  required String hmacSignatureSecret,
  CounterMode counterMode = CounterMode.uint32,
  HmacAlgorithm hmacAlgorithm = HmacAlgorithm.sha256,
  String? hmacKeySignatureSecret,
}) async {
  final start = DateTime.now();

  // 1. Expiration check.
  final expiresAt = challenge.parameters.expiresAt;
  if (expiresAt != null &&
      expiresAt < DateTime.now().millisecondsSinceEpoch ~/ 1000) {
    return VerifySolutionResult(
      expired: true,
      invalidSignature: null,
      invalidSolution: null,
      time: timeDuration(start),
      verified: false,
    );
  }

  // 2. Signature presence check.
  if (challenge.signature == null) {
    return VerifySolutionResult(
      expired: false,
      invalidSignature: true,
      invalidSolution: null,
      time: timeDuration(start),
      verified: false,
    );
  }

  // 3. Verify challenge signature.
  final signatureCheck = bufferToHex(
    hmacSignString(
      hmacAlgorithm,
      canonicalJson(challenge.parameters.toSortedJson()),
      hmacSignatureSecret,
    ),
  );
  if (!constantTimeEqual(challenge.signature!, signatureCheck)) {
    return VerifySolutionResult(
      expired: false,
      invalidSignature: true,
      invalidSolution: null,
      time: timeDuration(start),
      verified: false,
    );
  }

  // 4a. Key signature fast path.
  final keySignature = challenge.parameters.keySignature;
  if (keySignature != null && hmacKeySignatureSecret != null) {
    final derivedKeySignatureCheck = bufferToHex(
      hmacSign(
        hmacAlgorithm,
        hexToBuffer(solution.derivedKey),
        hmacKeySignatureSecret,
      ),
    );
    final valid = constantTimeEqual(keySignature, derivedKeySignatureCheck);
    return VerifySolutionResult(
      expired: false,
      invalidSignature: false,
      invalidSolution: !valid,
      time: timeDuration(start),
      verified: valid,
    );
  }

  // 4b. Re-derive and compare.
  final nonceBuf = hexToBuffer(challenge.parameters.nonce);
  final saltBuf = hexToBuffer(challenge.parameters.salt);
  final password =
      PasswordBuffer(nonceBuf, mode: counterMode == CounterMode.string ? 'string' : 'uint32')
          .setCounter(solution.counter);
  final result = await deriveKey(challenge.parameters, saltBuf, password);
  final derivedKeyHex = bufferToHex(result.derivedKey);
  final invalidSolution = !constantTimeEqual(derivedKeyHex, solution.derivedKey);

  return VerifySolutionResult(
    expired: false,
    invalidSignature: false,
    invalidSolution: invalidSolution,
    time: timeDuration(start),
    verified: !invalidSolution,
  );
}
