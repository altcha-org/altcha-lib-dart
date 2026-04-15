# ALTCHA Dart Library

A Dart implementation of the [ALTCHA](https://altcha.org) Proof-of-Work mechanism v2 for server-side challenge creation and verification.

## Installation

```sh
dart pub add altcha_lib
```

Or add manually to your `pubspec.yaml`:

```yaml
dependencies:
  altcha_lib: ^0.3.0
```

## Examples

- [`example/http_server.dart`](/example/http_server.dart)

## Usage

### Create a challenge

```dart
import 'dart:math';
import 'package:altcha_lib/altcha_lib.dart';
import 'package:altcha_lib/src/algorithms/pbkdf2.dart' as pbkdf2;

const hmacSecret = 'your-secret-key';

final challenge = await createChallenge(
  algorithm: 'PBKDF2/SHA-256',
  cost: 5000,
  counter: 5000 + Random.secure().nextInt(5000),
  deriveKey: pbkdf2.deriveKey,
  hmacSignatureSecret: hmacSecret,
);

// Serialize to JSON and send to the client.
print(challenge.toJson());
```

### Verify a solution

```dart
import 'dart:convert';
import 'package:altcha_lib/altcha_lib.dart';
import 'package:altcha_lib/src/algorithms/pbkdf2.dart' as pbkdf2;

const hmacSecret = 'your-secret-key';

// Decode the base64 payload sent by the ALTCHA widget.
final payloadJson = jsonDecode(utf8.decode(base64Decode(widgetPayload)));
final payload = Payload.fromJson(payloadJson);

final result = await verifySolution(
  challenge: payload.challenge,
  solution: payload.solution,
  deriveKey: pbkdf2.deriveKey,
  hmacSignatureSecret: hmacSecret,
);

if (result.verified) {
  print('Challenge verified!');
} else if (result.expired) {
  print('Challenge expired.');
} else if (result.invalidSignature == true) {
  print('Invalid signature — possible tampering.');
} else {
  print('Invalid solution.');
}
```

### Challenge with expiry

```dart
final challenge = await createChallenge(
  algorithm: 'PBKDF2/SHA-256',
  cost: 5000,
  deriveKey: pbkdf2.deriveKey,
  hmacSignatureSecret: hmacSecret,
  expiresAt: DateTime.now().add(const Duration(minutes: 10)),
);
```

### Server signature verification (ALTCHA Sentinel)

```dart
import 'package:altcha_lib/altcha_lib.dart';

final result = await verifyServerSignature(
  payload: ServerSignaturePayload.fromJson(payloadJson),
  hmacSecret: hmacSecret,
);

if (result.verified) {
  final data = result.verificationData;
  print('Score: ${data?['score']}');
}
```

### Solving challenges in parallel (Flutter / isolates)

`solveChallengeIsolates` spawns multiple [Dart Isolates](https://dart.dev/language/isolates) that race to solve the challenge in parallel, keeping the UI thread free. Each isolate tests an interleaved subset of counter values; the first to find a solution wins and all others are killed immediately.

```dart
import 'package:altcha_lib/altcha_lib.dart';
import 'package:altcha_lib/src/algorithms/pbkdf2.dart' as pbkdf2;

final solution = await solveChallengeIsolates(
  challenge: challenge,
  deriveKey: pbkdf2.deriveKey,
  concurrency: 4, // number of isolates; defaults to 1
);
```

> **Note:** `deriveKey` must be a top-level or static function. All built-in algorithm `deriveKey` functions qualify. Closures cannot be sent across isolate boundaries.

### Fields hash verification

```dart
final valid = await verifyFieldsHash(
  formData: {'email': 'user@example.com', 'message': 'Hello'},
  fields: ['email', 'message'],
  fieldsHash: receivedHash,
);
```

## Algorithms

| Algorithm identifier | Notes |
|---|---|
| `PBKDF2/SHA-256` | Recommended default |
| `PBKDF2/SHA-384` | Higher security |
| `PBKDF2/SHA-512` | Higher security |
| `SHA-256` | Fast, low cost — use higher iteration count |
| `SHA-384` | Fast hash-chain variant |
| `SHA-512` | Fast hash-chain variant |
| `SCRYPT` | Memory-hard; requires `memoryCost` and `parallelism` |
| `ARGON2ID` | Memory-hard; requires `memoryCost` and optionally `parallelism` |

Import the algorithm you need:

```dart
import 'package:altcha_lib/src/algorithms/pbkdf2.dart' as pbkdf2;
import 'package:altcha_lib/src/algorithms/sha.dart' as sha;
import 'package:altcha_lib/src/algorithms/scrypt.dart' as scrypt;
import 'package:altcha_lib/src/algorithms/argon2id.dart' as argon2id;
```

Or use `adaptiveDeriveKey` to dispatch automatically based on `ChallengeParameters.algorithm`:

```dart
import 'package:altcha_lib/algorithms.dart' show adaptiveDeriveKey;

final solution = await solveChallengeIsolates(
  challenge: challenge,
  deriveKey: adaptiveDeriveKey, // dispatches to PBKDF2, SHA, SCRYPT, or ARGON2ID
  concurrency: 4,
);
```

`adaptiveDeriveKey` is a top-level function and crosses isolate boundaries safely.

Scrypt requires additional parameters:

```dart
final challenge = await createChallenge(
  algorithm: 'SCRYPT',
  cost: 4096,       // N (must be power of 2)
  memoryCost: 8,    // r (block size)
  parallelism: 1,   // p
  deriveKey: scrypt.deriveKey,
  hmacSignatureSecret: hmacSecret,
);
```

Argon2id requires `memoryCost` (in KiB) and uses `cost` as the iteration count:

```dart
final challenge = await createChallenge(
  algorithm: 'ARGON2ID',
  cost: 2,          // iterations (time cost)
  memoryCost: 65536, // memory in KiB (64 MiB)
  parallelism: 1,   // lanes
  deriveKey: argon2id.deriveKey,
  hmacSignatureSecret: hmacSecret,
);
```

## API Reference

### `adaptiveDeriveKey`

Dispatches to the correct KDF based on `parameters.algorithm`. Import from `package:altcha_lib/algorithms.dart`.

```dart
Future<DeriveKeyResult> adaptiveDeriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
)
```

Supported algorithms (case-insensitive): `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`, `SHA-256`, `SHA-384`, `SHA-512`, `SCRYPT`, `ARGON2ID`. Throws `UnsupportedError` for unknown values.

### `createChallenge`

```dart
Future<Challenge> createChallenge({
  required String algorithm,
  required int cost,
  required DeriveKeyFunction deriveKey,
  int? counter,
  CounterMode counterMode,       // CounterMode.uint32 (default) or CounterMode.string
  Map<String, Object?>? data,
  Object? expiresAt,             // DateTime or int (Unix seconds)
  HmacAlgorithm hmacAlgorithm,   // default: HmacAlgorithm.sha256
  String? hmacKeySignatureSecret,
  String? hmacSignatureSecret,
  int keyLength,                 // default: 32
  String keyPrefix,              // default: '00'
  int? keyPrefixLength,
  int? memoryCost,
  int? parallelism,
})
```

### `solveChallenge`

```dart
Future<Solution?> solveChallenge({
  required Challenge challenge,
  required DeriveKeyFunction deriveKey,
  CounterMode counterMode,
  int counterStart,              // default: 0
  int counterStep,               // default: 1
  Duration timeout,              // default: 90 seconds
  Stream<void>? abortSignal,
})
```

Returns `null` on timeout or abort.

### `solveChallengeIsolates`

```dart
Future<Solution?> solveChallengeIsolates({
  required Challenge challenge,
  required DeriveKeyFunction deriveKey, // must be a top-level or static function
  int concurrency,                      // default: 1, max: 16
  CounterMode counterMode,
  Duration timeout,                     // default: 90 seconds
})
```

Returns `null` if all isolates time out without finding a solution.

### `verifySolution`

```dart
Future<VerifySolutionResult> verifySolution({
  required Challenge challenge,
  required Solution solution,
  required DeriveKeyFunction deriveKey,
  required String hmacSignatureSecret,
  CounterMode counterMode,
  HmacAlgorithm hmacAlgorithm,
  String? hmacKeySignatureSecret,
})
```

### `verifyServerSignature`

```dart
Future<VerifyServerSignatureResult> verifyServerSignature({
  required ServerSignaturePayload payload,
  required String hmacSecret,
})
```

### `verifyFieldsHash`

```dart
Future<bool> verifyFieldsHash({
  required Map<String, dynamic> formData,
  required List<String> fields,
  required String fieldsHash,
  String algorithm,              // default: 'SHA-256'
})
```

## Requirements

- Dart SDK `>=3.0.0`
- Dependencies: [`crypto`](https://pub.dev/packages/crypto), [`pointycastle`](https://pub.dev/packages/pointycastle)

## License

MIT
