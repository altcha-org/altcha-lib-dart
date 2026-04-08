import 'package:test/test.dart';

import 'package:altcha_lib/src/pow.dart';
import 'package:altcha_lib/src/algorithms/argon2id.dart' as argon2id;

const hmacSecret = 'signature.secret';

void main() {
  group('argon2id', () {
    test('creates and solves a challenge', () async {
      final challenge = await createChallenge(
        algorithm: 'ARGON2ID',
        cost: 2,
        memoryCost: 256, // 256 KiB
        parallelism: 1,
        deriveKey: argon2id.deriveKey,
        hmacSignatureSecret: hmacSecret,
      );
      expect(challenge.signature, isNotNull);

      final solution = await solveChallenge(
        challenge: challenge,
        deriveKey: argon2id.deriveKey,
      );
      expect(solution, isNotNull);
      expect(solution!.derivedKey.length, equals(64));

      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: argon2id.deriveKey,
        hmacSignatureSecret: hmacSecret,
      );
      expect(result.verified, isTrue);
    });
  });
}
