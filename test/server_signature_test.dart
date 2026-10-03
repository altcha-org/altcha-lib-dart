import 'dart:convert';

import 'package:test/test.dart';

import 'package:altcha_lib/src/helpers.dart';
import 'package:altcha_lib/src/server_signature.dart';
import 'package:altcha_lib/src/types.dart';

const verificationData = 'verified=true&score=1';

ServerSignaturePayload payloadSignedWith(String secret) =>
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
        payload: payloadSignedWith('server.secret'),
        hmacSecret: 'server.secret',
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
  });
}
