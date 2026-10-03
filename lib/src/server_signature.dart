import 'dart:convert';

import 'helpers.dart';
import 'types.dart';

/// Parses a URL-encoded verification data string into a typed map.
///
/// Fields listed in [convertToArray] are split on commas.
Map<String, dynamic>? parseVerificationData(
  String data, {
  List<String> convertToArray = const ['fields', 'reasons'],
}) {
  try {
    final result = <String, dynamic>{};
    final params = Uri.splitQueryString(data);
    for (final entry in params.entries) {
      final key = entry.key;
      final value = entry.value;
      if (value == 'true' || value == 'false') {
        result[key] = value == 'true';
      } else if (RegExp(r'^\d+$').hasMatch(value)) {
        result[key] = int.parse(value);
      } else if (RegExp(r'^\d+\.\d+$').hasMatch(value)) {
        result[key] = double.parse(value);
      } else {
        result[key] = convertToArray.contains(key) && value.isNotEmpty
            ? value.trim().split(',')
            : value.trim();
      }
    }
    return result;
  } catch (_) {
    return null;
  }
}

/// Verifies a hash of form fields.
Future<bool> verifyFieldsHash({
  required Map<String, dynamic> formData,
  required List<String> fields,
  required String fieldsHash,
  String algorithm = 'SHA-256',
}) async {
  final lines = fields.map((f) => '${formData[f] ?? ''}').join('\n');
  final digest = bufferToHex(hashData(algorithm, utf8.encode(lines)));
  return digest == fieldsHash;
}

/// Verifies a server-issued ALTCHA signature payload.
///
/// An empty [hmacSecret] is treated as unset: the result is `invalidSignature`,
/// since anyone can compute an HMAC under the empty key.
Future<VerifyServerSignatureResult> verifyServerSignature({
  required ServerSignaturePayload payload,
  required String hmacSecret,
}) async {
  final start = DateTime.now();
  final algorithm = HmacAlgorithm.fromString(payload.algorithm);

  final dataHash =
      hashData(payload.algorithm, utf8.encode(payload.verificationData));
  final invalidSignature = hmacSecret.isEmpty ||
      !constantTimeEqual(
        payload.signature,
        bufferToHex(hmacSign(algorithm, dataHash, hmacSecret)),
      );

  final verificationData = parseVerificationData(payload.verificationData);

  final expired = _isExpired(verificationData?['expire']);

  final invalidSolution = verificationData == null ||
      verificationData['verified'] != true ||
      payload.verified != true;

  final verified = !expired && !invalidSignature && !invalidSolution;

  return VerifyServerSignatureResult(
    expired: expired,
    invalidSignature: invalidSignature,
    invalidSolution: invalidSolution,
    time: timeDuration(start),
    verified: verified,
    verificationData: verificationData,
  );
}

/// altcha-lib's `!!expire && expire < Math.floor(Date.now() / 1000)` for the
/// value types [parseVerificationData] yields. `expire` is client-controlled
/// until the signature is checked, so this must not throw.
bool _isExpired(Object? expire) {
  final num? value = switch (expire) {
    num n => n,
    bool b => b ? 1 : 0,
    // JS coerces strings to numbers; non-numeric ones never compare as less.
    String s => s.isEmpty ? 0 : num.tryParse(s),
    _ => null,
  };
  return value != null &&
      value != 0 &&
      value < DateTime.now().millisecondsSinceEpoch ~/ 1000;
}
