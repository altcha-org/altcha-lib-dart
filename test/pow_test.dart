import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:altcha_lib/src/helpers.dart';
import 'package:altcha_lib/src/password_buffer.dart';
import 'package:altcha_lib/src/pow.dart';
import 'package:altcha_lib/src/pow_io.dart';
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

    test('canonicalJson matches JSON.stringify(sortKeys(...))', () {
      final obj = <String, dynamic>{
        'n': {'z': 1, 'y': 1.0},
        'a': 1.5,
        'b': -0.0,
        'c': 1e20,
        'd': 1e21,
        'e': 1e-7,
        'f': 0.000001,
        'g': -2,
        'h': 123456789012345680000.0,
        'l': [
          {'z': 1, 'y': 2},
          3.0,
        ],
        's': 'x\u2028"',
      };
      // Output of altcha-lib (JS) canonicalJSON for the same object.
      expect(
        canonicalJson(obj),
        equals('{"a":1.5,"b":0,"c":100000000000000000000,"d":1e+21,'
            '"e":1e-7,"f":0.000001,"g":-2,"h":123456789012345680000,'
            '"l":[{"z":1,"y":2},3],"n":{"y":1,"z":1},"s":"x\u2028\\""}'),
      );
    });

    test('canonicalJson orders keys like JS objects', () {
      // Array-index keys first (numerically), then the rest sorted; JS
      // sortKeys drops `__proto__`; objects inside lists stay unsorted but
      // still enumerate index keys first.
      final obj = jsonDecode('{"b":1,"10":1,"9":2,"4294967294":3,'
          '"4294967295":4,"-1":5,"01":6,"1.5":7,"a":8,"__proto__":9,'
          '"l":[{"x":1,"10":2,"9":3,"__proto__":4}]}') as Map<String, dynamic>;
      // Output of altcha-lib (JS) canonicalJSON(JSON.parse(...)).
      expect(
        canonicalJson(obj),
        equals('{"9":2,"10":1,"4294967294":3,"-1":5,"01":6,"1.5":7,'
            '"4294967295":4,"a":8,"b":1,'
            '"l":[{"9":3,"10":2,"x":1,"__proto__":4}]}'),
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

    test('signs nested data like altcha-lib (sorted keys, nulls kept)',
        () async {
      final parameters = ChallengeParameters(
        algorithm: 'PBKDF2/SHA-256',
        nonce: '39baf91a19d671f8231217f9e28342a6',
        salt: '5e00d5d152e1a5db7d44fb6404a40a5e',
        keyPrefix: '00',
        cost: 1000,
        keyLength: 32,
        data: {
          'b': 'x',
          'a': null,
          'c': {'z': 1, 'y': true},
        },
      );
      final result = await signChallenge(
        HmacAlgorithm.sha256,
        parameters,
        null,
        hmacSignatureSecret,
        null,
      );
      // Computed with altcha-lib (JS) v2 canonicalJSON + HMAC-SHA256.
      expect(
        result.signature,
        equals(
            'd6a70784812667316e8baa50479afcf9b61f1e44d3d4737b51b4400595a7a6b2'),
      );
    });

    test('rejects an empty hmacSignatureSecret', () {
      final parameters = ChallengeParameters(
        algorithm: 'PBKDF2/SHA-256',
        nonce: '39baf91a19d671f8231217f9e28342a6',
        salt: '5e00d5d152e1a5db7d44fb6404a40a5e',
        keyPrefix: '00',
        cost: 1000,
        keyLength: 32,
      );
      expect(
        () => signChallenge(HmacAlgorithm.sha256, parameters, null, '', null),
        throwsArgumentError,
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

    test('treats empty secrets as unset', () async {
      final unsigned = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: 5,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: '',
        hmacKeySignatureSecret: '',
      );
      expect(unsigned.signature, isNull);
      expect(unsigned.parameters.keySignature, isNull);

      final signed = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: 5,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: '',
      );
      expect(signed.signature, isNotNull);
      expect(signed.parameters.keySignature, isNull);
    });

    test('ignores extra keys that name modelled parameters', () async {
      ChallengeParameters params(Map<String, Object?> extra) =>
          ChallengeParameters(
            algorithm: 'PBKDF2/SHA-256',
            nonce: '39baf91a19d671f8231217f9e28342a6',
            salt: '5e00d5d152e1a5db7d44fb6404a40a5e',
            keyPrefix: '00',
            cost: 1000,
            keyLength: 32,
            extra: extra,
          );
      final shadowed = params({'foo': 'bar', 'memoryCost': 5, 'keyPrefix': ''});
      expect(shadowed.toJson(), equals(params({'foo': 'bar'}).toJson()));
    });

    test('merges all parameters returned by deriveKey', () async {
      Future<DeriveKeyResult> deriveKey(ChallengeParameters parameters,
          List<int> salt, List<int> password) async {
        final result = await pbkdf2.deriveKey(parameters, salt, password);
        return DeriveKeyResult(
          derivedKey: result.derivedKey,
          parameters: {'foo': 'bar', 'memoryCost': 7},
        );
      }

      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        counter: 5,
        deriveKey: deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      final wire = Challenge.fromJson(
        jsonDecode(jsonEncode(challenge.toJson())) as Map<String, dynamic>,
      );
      expect(wire.parameters.toJson()['foo'], equals('bar'));
      expect(wire.parameters.memoryCost, equals(7));

      final result = await verifySolution(
        challenge: wire,
        solution: (await solveChallenge(
          challenge: wire,
          deriveKey: pbkdf2.deriveKey,
        ))!,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      expect(result.verified, isTrue);
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

    test('treats a zero timeout as no timeout', () async {
      final challenge = Challenge(
        parameters: ChallengeParameters(
          algorithm: 'PBKDF2/SHA-256',
          nonce: 'aabbccdd00112233aabbccdd00112233',
          salt: '11223344556677889900aabbccddeeff',
          keyPrefix: 'a',
          cost: 1000,
          keyLength: 32,
        ),
      );
      final solution = await solveChallenge(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
        timeout: Duration.zero,
      );
      expect(solution?.counter, equals(20));
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

    test('verifies a challenge with unsorted and null data', () async {
      final challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 100,
        deriveKey: pbkdf2.deriveKey,
        data: {'b': '1', 'a': null},
        hmacSignatureSecret: hmacSignatureSecret,
      );
      final wire = Challenge.fromJson(
        jsonDecode(jsonEncode(challenge.toJson())) as Map<String, dynamic>,
      );
      final solution = (await solveChallenge(
        challenge: wire,
        deriveKey: pbkdf2.deriveKey,
      ))!;
      final result = await verifySolution(
        challenge: wire,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      expect(result.invalidSignature, isFalse);
      expect(result.verified, isTrue);
    });

    // Signatures computed with altcha-lib (JS) v2 over the test vector
    // (counter 42 → derivedKey f2e25aab…).
    final jsSolution = Solution(
      counter: 42,
      derivedKey:
          'f2e25aab6d5e504747ad0f52b1ce42afd99d8014634f263ea42b206300037acf',
    );
    Challenge jsChallenge(String extraJson, String signature) =>
        Challenge.fromJson(jsonDecode('{"parameters":{'
            '"algorithm":"PBKDF2/SHA-256","cost":1000,"keyLength":32,'
            '"keyPrefix":"f2","nonce":"aabbccdd00112233aabbccdd00112233",'
            '"salt":"11223344556677889900aabbccddeeff",$extraJson},'
            '"signature":"$signature"}') as Map<String, dynamic>);

    test('verifies JS challenges with unknown parameter keys', () async {
      final result = await verifySolution(
        challenge: jsChallenge('"foo":"bar","baz":null',
            '0c7009c9e214b0e13cfbf090f98092e8e2bd1e6f6fe0068889c0f32e77d45606'),
        solution: jsSolution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      expect(result.invalidSignature, isFalse);
      expect(result.verified, isTrue);
    });

    test('verifies JS challenges with fractional expiresAt', () async {
      final result = await verifySolution(
        challenge: jsChallenge('"expiresAt":4102444800.5',
            '26384612047825a4d4fee2599357fafde1876d4ef2033b90e4d44753d464f21b'),
        solution: jsSolution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      expect(result.invalidSignature, isFalse);
      expect(result.verified, isTrue);
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

    test('rejects malformed derivedKey on the key-signature path', () async {
      final (:challenge, :solution) = await solve(100);
      for (final derivedKey in ['zz' * 32, 'abc', '-1' * 32, '+f' * 32]) {
        final result = await verifySolution(
          challenge: challenge,
          solution: Solution(counter: solution.counter, derivedKey: derivedKey),
          deriveKey: pbkdf2.deriveKey,
          hmacSignatureSecret: hmacSignatureSecret,
          hmacKeySignatureSecret: hmacKeySecret,
        );
        expect(result.verified, isFalse, reason: derivedKey);
        expect(result.invalidSignature, isFalse, reason: derivedKey);
        expect(result.invalidSolution, isTrue, reason: derivedKey);
      }
    });

    test('compares even-length keyPrefix as bytes (case-insensitive)',
        () async {
      Future<Challenge> signed(String keyPrefix) => signChallenge(
            HmacAlgorithm.sha256,
            ChallengeParameters(
              algorithm: 'PBKDF2/SHA-256',
              nonce: 'aabbccdd00112233aabbccdd00112233',
              salt: '11223344556677889900aabbccddeeff',
              keyPrefix: keyPrefix,
              cost: 1000,
              keyLength: 32,
            ),
            null,
            hmacSignatureSecret,
            null,
          );
      final challenge = await signed('F2');
      final solution = (await solveChallenge(
        challenge: challenge,
        deriveKey: pbkdf2.deriveKey,
      ))!;
      expect(solution.counter, equals(42));
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      expect(result.verified, isTrue);

      // A malformed signed prefix fails closed instead of throwing.
      final malformed = await verifySolution(
        challenge: await signed('zz'),
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
      );
      expect(malformed.invalidSignature, isFalse);
      expect(malformed.invalidSolution, isTrue);
    });

    test('fails when expired', () async {
      final expiredAt = DateTime.now()
              .subtract(const Duration(seconds: 1))
              .millisecondsSinceEpoch ~/
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

    test('expires within the current second (no rounding grace)', () async {
      final (:challenge, :solution) =
          await solve(null, DateTime.now().millisecondsSinceEpoch ~/ 1000);
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

    test('treats expiresAt 0 as no expiry', () async {
      final (:challenge, :solution) = await solve(null, 0);
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: hmacKeySecret,
      );
      expect(result.expired, isFalse);
      expect(result.verified, isTrue);
    });

    test('re-derives when hmacKeySignatureSecret is empty', () async {
      final (:challenge, :solution) = await solve(100);
      expect(challenge.parameters.keySignature, isNotNull);
      final result = await verifySolution(
        challenge: challenge,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
        hmacKeySignatureSecret: '',
      );
      expect(result.verified, isTrue);
    });

    test('rejects challenges when hmacSignatureSecret is empty', () async {
      // Anyone can produce an HMAC under the empty key.
      final (:challenge, :solution) = await solve();
      final forged = Challenge(
        parameters: challenge.parameters,
        signature: bufferToHex(hmacSignString(
          HmacAlgorithm.sha256,
          canonicalJson(challenge.parameters.toJson()),
          '',
        )),
      );
      final result = await verifySolution(
        challenge: forged,
        solution: solution,
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: '',
      );
      expect(result.verified, isFalse);
      expect(result.invalidSignature, isTrue);
      expect(result.invalidSolution, isNull);
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

    test('fallback path rejects genuinely-derived key that violates keyPrefix',
        () async {
      // No hmacKeySignatureSecret -> forces the slow re-derive path (4b).
      var challenge = await createChallenge(
        algorithm: 'PBKDF2/SHA-256',
        cost: 10,
        deriveKey: pbkdf2.deriveKey,
      );

      // Learn the honest KDF output for counter 0 with exactly one hash
      // computation: solve a probe copy of the challenge whose keyPrefix is
      // '' (matches immediately, no search).
      final probe =
          Challenge(parameters: challenge.parameters.copyWith(keyPrefix: ''));
      final honest = (await solveChallenge(
        challenge: probe,
        deriveKey: pbkdf2.deriveKey,
      ))!;

      // Pick a keyPrefix the honest key is guaranteed not to satisfy: a byte
      // can't be both 0x00 and 0xff.
      final mismatchedPrefix = honest.derivedKey.startsWith('00') ? 'ff' : '00';
      challenge = Challenge(
        parameters: challenge.parameters.copyWith(keyPrefix: mismatchedPrefix),
      );
      final signed = await signChallenge(
        HmacAlgorithm.sha256,
        challenge.parameters,
        null,
        hmacSignatureSecret,
        null,
      );

      // Submit the honestly-derived key/counter pair (one KDF execution, no
      // prefix search) against the challenge whose signed keyPrefix it does
      // not satisfy.
      final result = await verifySolution(
        challenge: signed,
        solution:
            Solution(counter: honest.counter, derivedKey: honest.derivedKey),
        deriveKey: pbkdf2.deriveKey,
        hmacSignatureSecret: hmacSignatureSecret,
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
