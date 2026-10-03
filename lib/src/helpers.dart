import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'types.dart';

/// Checks if [buffer] starts with [prefix].
bool bufferStartsWith(List<int> buffer, List<int> prefix) {
  if (prefix.length > buffer.length) return false;
  for (var i = 0; i < prefix.length; i++) {
    if (buffer[i] != prefix[i]) return false;
  }
  return true;
}

/// Converts a byte list to a lowercase hex string.
String bufferToHex(List<int> buffer) {
  return buffer.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Converts a hex string to a [Uint8List].
Uint8List hexToBuffer(String hex) {
  if (hex.length % 2 != 0) {
    throw ArgumentError('Hex string must have even length, got: $hex');
  }
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

/// Strictly decodes an even-length hex string (`[0-9a-fA-F]` only).
/// Returns null for anything else, so untrusted input never throws.
Uint8List? tryHexToBuffer(String hex) {
  if (hex.length.isOdd) return null;
  final result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    final hi = _hexNibble(hex.codeUnitAt(i));
    final lo = _hexNibble(hex.codeUnitAt(i + 1));
    if (hi < 0 || lo < 0) return null;
    result[i ~/ 2] = (hi << 4) | lo;
  }
  return result;
}

int _hexNibble(int c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30; // 0-9
  if (c >= 0x61 && c <= 0x66) return c - 0x57; // a-f
  if (c >= 0x41 && c <= 0x46) return c - 0x37; // A-F
  return -1;
}

/// Concatenates two byte lists.
Uint8List concatBuffers(List<int> a, List<int> b) {
  final result = Uint8List(a.length + b.length);
  result.setAll(0, a);
  result.setAll(a.length, b);
  return result;
}

/// Constant-time string comparison.
bool constantTimeEqual(String a, String b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return result == 0;
}

/// Computes an HMAC-SHA signature.
List<int> hmacSign(HmacAlgorithm algorithm, List<int> data, String keyStr) {
  final keyBytes = utf8.encode(keyStr);
  final hmac = _getHmac(algorithm, keyBytes);
  return hmac.convert(data).bytes;
}

/// Computes an HMAC-SHA signature from a string message.
List<int> hmacSignString(
    HmacAlgorithm algorithm, String data, String keyStr) {
  return hmacSign(algorithm, utf8.encode(data), keyStr);
}

crypto.Hmac _getHmac(HmacAlgorithm algorithm, List<int> key) {
  switch (algorithm) {
    case HmacAlgorithm.sha384:
      return crypto.Hmac(crypto.sha384, key);
    case HmacAlgorithm.sha512:
      return crypto.Hmac(crypto.sha512, key);
    case HmacAlgorithm.sha256:
      return crypto.Hmac(crypto.sha256, key);
  }
}

/// Computes a SHA hash.
List<int> hashData(String algorithm, List<int> data) {
  switch (algorithm.toUpperCase()) {
    case 'SHA-512':
      return crypto.sha512.convert(data).bytes;
    case 'SHA-384':
      return crypto.sha384.convert(data).bytes;
    default:
      return crypto.sha256.convert(data).bytes;
  }
}

/// Generates a random integer in [min, max] (inclusive).
int randomInt(int max, {int min = 1}) {
  final rng = Random.secure();
  return min + rng.nextInt(max - min + 1);
}

/// Generates cryptographically random bytes.
Uint8List randomBytes(int length) {
  final rng = Random.secure();
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = rng.nextInt(256);
  }
  return bytes;
}

/// Returns a canonical JSON string: map keys sorted recursively, matching
/// altcha-lib's `canonicalJSON`. Null values are kept (JS drops only
/// `undefined`, which has no Dart counterpart).
String canonicalJson(Map<String, dynamic> obj) {
  return jsonEncode(sortKeys(obj));
}

/// Recursively sorts map keys alphabetically. Lists are left as-is.
dynamic sortKeys(dynamic value) {
  if (value is Map) {
    return Map<String, dynamic>.fromEntries(
      (value.entries.toList()
            ..sort((a, b) => (a.key as String).compareTo(b.key as String)))
          .map((e) => MapEntry(e.key as String, sortKeys(e.value))),
    );
  }
  return value;
}

/// Returns elapsed milliseconds since [start] (Stopwatch-based), rounded to 1 decimal.
double timeDuration(DateTime start) {
  final ms = DateTime.now().difference(start).inMicroseconds / 1000.0;
  return (ms * 10).floorToDouble() / 10;
}
