import 'dart:convert';

import 'package:test/test.dart';

import 'package:altcha_lib/src/helpers.dart';
import 'package:altcha_lib/src/server_signature.dart';
import 'package:altcha_lib/src/types.dart';

const hmacSecret = 'server.secret';

ServerSignaturePayload payloadSignedWith(
  String secret, [
  String verificationData = 'verified=true&score=1',
]) =>
    ServerSignaturePayload(
      algorithm: 'SHA-256',
      signature: bufferToHex(hmacSign(
        HmacAlgorithm.sha256,
        hashData('SHA-256', utf8.encode(verificationData)),
        secret,
      )),
      verificationData: verificationData,
      verified: true,
    );

void main() {
  group('verifyServerSignature()', () {
    test('verifies a payload signed with the secret', () async {
      final result = await verifyServerSignature(
        payload: payloadSignedWith(hmacSecret),
        hmacSecret: hmacSecret,
      );
      expect(result.verified, isTrue);
      expect(result.invalidSignature, isFalse);
    });

    test('rejects payloads when hmacSecret is empty', () async {
      // Anyone can produce an HMAC under the empty key.
      final result = await verifyServerSignature(
        payload: payloadSignedWith(''),
        hmacSecret: '',
      );
      expect(result.verified, isFalse);
      expect(result.invalidSignature, isTrue);
    });

    test('evaluates expire like altcha-lib', () async {
      // expire value → expired, as returned by altcha-lib (JS).
      const cases = {
        '1.5': true,
        '4102444800.5': false,
        '4102444800': false,
        '1': true,
        '0': false,
        'abc': false,
        '': false,
        'true': true,
        'false': false,
        '-5': true,
      };
      for (final MapEntry(key: expire, value: expired) in cases.entries) {
        final result = await verifyServerSignature(
          payload:
              payloadSignedWith(hmacSecret, 'verified=true&expire=$expire'),
          hmacSecret: hmacSecret,
        );
        expect(result.expired, expired, reason: 'expire=$expire');
        expect(result.verified, !expired, reason: 'expire=$expire');
      }
    });

    test('rejects forged payloads with a non-integer expire', () async {
      for (final expire in ['1.5', 'abc', '']) {
        final result = await verifyServerSignature(
          payload: payloadSignedWith('forged', 'verified=true&expire=$expire'),
          hmacSecret: hmacSecret,
        );
        expect(result.invalidSignature, isTrue, reason: 'expire=$expire');
        expect(result.verified, isFalse, reason: 'expire=$expire');
      }
    });
  });
}
