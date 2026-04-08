import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:altcha_lib/src/helpers.dart';
import 'package:altcha_lib/src/password_buffer.dart';
import 'package:altcha_lib/src/pow.dart';
import 'package:altcha_lib/src/types.dart';
import 'package:altcha_lib/src/algorithms/pbkdf2.dart' as pbkdf2;

const hmacSignatureSecret = 'signature.secret';
const hmacKeySecret = 'key.secret';

void main() {
  group('helpers', () {
    test('bufferToHex returns hex string', () {
      final bytes = 'Hello World'.codeUnits;
      expect(bufferToHex(bytes), equals('48656c6c6f20576f726c64'));
    });

    test('hexToBuffer returns correct bytes', () {
      final result = hexToBuffer('48656c6c6f20576f726c64');
      expect(result, equals(Uint8List.fromList('Hello World'.codeUnits)));
    });

    test('concatBuffers returns concatenated bytes', () {
      final a = Uint8List.fromList('Hello'.codeUnits);
      final b = Uint8List.fromList(' World'.codeUnits);
      expect(concatBuffers(a, b),
          equals(Uint8List.fromList('Hello World'.codeUnits)));
    });

    test('canonicalJson sorts keys', () {
      final obj = <String, dynamic>{
        'a': 'a',
        'c': 'c',
        'b': 'b',
        'B': 'B',
        'x': {'a': 'a', 'f': 'f', 'c': 'c'},
      };
      final result = canonicalJson(obj);
      expect(
        result,
        equals(
          '{"B":"B","a":"a","b":"b","c":"c","x":{"a":"a","c":"c","f":"f"}}',
        ),
      );
    });
  });

  group('signChallenge()', () {
    test('returns a signed challenge', () async {
      final parameters = ChallengeParameters(
        algorithm: 'PBKDF2/SHA-256',
        nonce: '39baf91a19d671f8231217f9e28342a6',
        salt: '5e00d5d152e1a5db7d44fb6404a40a5e',
        keyPrefix: '00',
        cost: 1000,
        keyLength: 32,
      );
      final result = await signChallenge(
        HmacAlgorithm.sha256,
        parameters,
        null,
        hmacSignatureSecret,
        hmacKeySecret,
      );
      expect(result.signature, isNotNull);
      expect(
        result.signature,
        equals(
            'a10045ef3381d5516e0c3fd6bf0b90e02fab68d576ffe9e0e1c2d1cd1e404f2a'),
      );
    });
  });

  group('createChallenge()', () {
    test('returns a challenge without signature', () async {
      final result = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 1000,
        deriveKey: pbkdf2.deriveKey,
      );
      expect(result.parameters.algorithm, equals('PBKDF2/SHA-256'));
      expect(result.parameters.cost, equals(1000));
      expect(result.parameters.keyLength, equals(32));
      expect(result.parameters.keyPrefix, equals('00'));
      expect(result.parameters.nonce.length, equals(32));
      expect(result.parameters.salt.length, equals(32));
      expect(result.signature, isNull);
    });

    test('returns a challenge with fixed counter', () async {
      final result = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 1000,
        counter: 1000,
        deriveKey: pbkdf2.deriveKey,
      );
      expect(result.parameters.keyPrefix.length, equals(32));
      expect(result.signature, isNull);
    });

    test('returns a challenge with signature', () async {
      final result = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 1000,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.signature, isNotNull);
      expect(result.signature!.length, equals(64));
      expect(result.parameters.nonce.length, equals(32));
      expect(result.parameters.salt.length, equals(32));
    });

    test('returns a deterministic challenge with key signature', () async {
      final result = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 1000,
        counter: 1000,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.parameters.keyPrefix.length, equals(32));
      expect(result.parameters.keySignature?.length, equals(64));
      expect(result.signature?.length, equals(64));
    });
  });

  group('solveChallenge()', () {
    test('returns a solution', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        deriveKey: pbkdf2.deriveKey,
      );
      final solution = await solveChallenge(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
      );
      expect(solution, isNotNull);
      expect(solution!.counter, isA<int>());
      expect(solution.derivedKey.length, equals(64));
    });

    test('times out and returns null', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: 1000000,
        deriveKey: pbkdf2.deriveKey,
      );
      final solution = await solveChallenge(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
        timeout: const Duration(seconds: 1),
      );
      expect(solution, isNull);
    });
  });

  group('verifySolution()', () {
    Future<({Challenge challenge, Solution solution})> solve([
      int? counter,
      int? expiresAt,
    ]) async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: counter,
        expiresAt: expiresAt,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      final solution = (await solveChallenge(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
      ))!;
      return (challenge: challenge, solution: solution);
    }

    test('successfully verifies', () async {
      final (:challenge, :solution) = await solve();
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.verified, isTrue);
      expect(result.expired, isFalse);
      expect(result.invalidSignature, isFalse);
      expect(result.invalidSolution, isFalse);
    });

    test('successfully verifies in deterministic mode', () async {
      final (:challenge, :solution) = await solve(100);
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.verified, isTrue);
    });

    test('fails with invalid HMAC key', () async {
      final (:challenge, :solution) = await solve();
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: '${hmacSignatureSecret}invalid',
        hmacKeySignatureSecret: '${hmacKeySecret}invalid',
      );
      expect(result.verified, isFalse);
      expect(result.invalidSignature, isTrue);
      expect(result.invalidSolution, isNull);
    });

    test('fails with wrong solution counter', () async {
      final (:challenge, :solution) = await solve();
      final result = await verifySolution(
        challenge: challenge,
        solution: Solution(
          counter: solution.counter + 1,
          derivedKey: solution.derivedKey,
        ),
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.verified, isFalse);
      expect(result.invalidSolution, isTrue);
    });

    test('fails when expired', () async {
      final expiredAt =
          DateTime.now().subtract(const Duration(seconds: 1)).millisecondsSinceEpoch ~/
              1000;
      final (:challenge, :solution) = await solve(null, expiredAt);
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.expired, isTrue);
      expect(result.verified, isFalse);
    });

    test('fails with tampered keyPrefix', () async {
      final (:challenge, :solution) = await solve();
      final tampered = Challenge(
        parameters: challenge.parameters.copyWith(keyPrefix: 'a'),
        signature: challenge.signature,
      );
      final result = await verifySolution(
        challenge: tampered,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.verified, isFalse);
      expect(result.invalidSignature, isTrue);
    });

    test('fails with spoofed solution in deterministic mode', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: 100,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      final result = await verifySolution(
        challenge: challenge,
        solution: Solution(
          counter: 100,
          derivedKey: challenge.parameters.keyPrefix,
          time: 10,
        ),
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.verified, isFalse);
      expect(result.invalidSolution, isTrue);
    });
  });

  group('solveChallengeIsolates()', () {
    test('returns a solution using a single isolate', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        deriveKey: pbkdf2.deriveKey,
      );
      final solution = await solveChallengeIsolates(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
        concurrency: 1,
      );
      expect(solution, isNotNull);
      expect(solution!.derivedKey.length, equals(64));
    });

    test('returns a solution using multiple isolates', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        deriveKey: pbkdf2.deriveKey,
      );
      final solution = await solveChallengeIsolates(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
        concurrency: 4,
      );
      expect(solution, isNotNull);
      expect(solution!.derivedKey.length, equals(64));
    });

    test('solution is verifiable', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      final solution = (await solveChallengeIsolates(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
        concurrency: 2,
      ))!;
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.verified, isTrue);
    });

    test('times out and returns null', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: 1000000,
        deriveKey: pbkdf2.deriveKey,
      );
      final solution = await solveChallengeIsolates(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
        concurrency: 2,
        timeout: const Duration(seconds: 1),
      );
      expect(solution, isNull);
    });
  });

  group('PasswordBuffer', () {
    test('uint32 mode (single byte)', () {
      const counter = 123;
      final nonce = randomBytes(16);
      final buf = PasswordBuffer(nonce).setCounter(counter);
      expect(buf.sublist(buf.length - 4), equals([0, 0, 0, counter]));
    });

    test('uint32 mode (multi-byte)', () {
      const counter = 9999999;
      final nonce = randomBytes(16);
      final buf = PasswordBuffer(nonce).setCounter(counter);
      final dv = ByteData.view(Uint8List.fromList(buf).buffer);
      expect(dv.getUint32(nonce.length, Endian.big), equals(counter));
    });
  });
}
