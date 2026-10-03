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

/// Returns a canonical JSON string matching altcha-lib's `canonicalJSON`
/// (`JSON.stringify(sortKeys(obj))`): map keys sorted recursively, nulls kept
/// (JS drops only `undefined`, which has no Dart counterpart), and numbers
/// formatted as in JS.
String canonicalJson(Map<String, dynamic> obj) {
  final out = StringBuffer();
  _writeJson(out, sortKeys(obj));
  return out.toString();
}

/// Writes [value] as compact JSON, with map keys in JS enumeration order.
void _writeJson(StringBuffer out, Object? value) {
  if (value is Map) {
    out.write('{');
    var first = true;
    for (final key in _jsPropertyOrder(value.keys.cast<String>())) {
      if (!first) out.write(',');
      first = false;
      out
        ..write(jsonEncode(key))
        ..write(':');
      _writeJson(out, value[key]);
    }
    out.write('}');
  } else if (value is List) {
    out.write('[');
    for (var i = 0; i < value.length; i++) {
      if (i > 0) out.write(',');
      _writeJson(out, value[i]);
    }
    out.write(']');
  } else if (value is double && value.isFinite) {
    // Dart's shortest round-trip format (same exponent thresholds as JS)
    // differs from JS only by the `.0` on integral values and `-0.0`.
    if (value == 0) {
      out.write('0');
    } else {
      final s = value.toString();
      out.write(s.endsWith('.0') ? s.substring(0, s.length - 2) : s);
    }
  } else {
    out.write(jsonEncode(value));
  }
}

/// Recursively sorts map keys like altcha-lib's `sortKeys`, as JS then
/// enumerates them: array-index keys (`"0"`…`"4294967294"`) in numeric order,
/// then all other keys sorted by UTF-16 code units. `__proto__` is dropped
/// (in JS, assigning it sets the prototype instead of adding a key).
/// Lists are left as-is.
dynamic sortKeys(dynamic value) {
  if (value is Map) {
    final keys = value.keys.cast<String>().where((k) => k != '__proto__').toList()
      ..sort();
    return <String, dynamic>{
      for (final key in _jsPropertyOrder(keys)) key: sortKeys(value[key]),
    };
  }
  return value;
}

final _arrayIndexPattern = RegExp(r'^(?:0|[1-9][0-9]{0,9})$');

/// Returns [key] as an ECMAScript array index (0 ≤ i ≤ 2^32 − 2), or null.
int? _arrayIndex(String key) {
  if (!_arrayIndexPattern.hasMatch(key)) return null;
  final index = int.parse(key);
  return index <= 4294967294 ? index : null;
}

/// Orders [keys] the way JS enumerates an object's own properties: array-index
/// keys in ascending numeric order, then the rest in their given order.
List<String> _jsPropertyOrder(Iterable<String> keys) {
  final indexed = <(int, String)>[];
  final rest = <String>[];
  for (final key in keys) {
    final index = _arrayIndex(key);
    if (index != null) {
      indexed.add((index, key));
    } else {
      rest.add(key);
    }
  }
  if (indexed.isEmpty) return rest;
  indexed.sort((a, b) => a.$1.compareTo(b.$1));
  return [for (final (_, key) in indexed) key, ...rest];
}

/// Returns elapsed milliseconds since [start] (Stopwatch-based), rounded to 1 decimal.
double timeDuration(DateTime start) {
  final ms = DateTime.now().difference(start).inMicroseconds / 1000.0;
  return (ms * 10).floorToDouble() / 10;
}
