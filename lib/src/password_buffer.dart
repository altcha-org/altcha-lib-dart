import 'dart:convert';
import 'dart:typed_data';

import 'helpers.dart';

/// Manages a buffer that combines a nonce with a counter value.
/// Used to generate unique passwords for each iteration of the challenge solver.
class PasswordBuffer {
  static const _counterBytes = 4;

  final Uint8List nonce;
  final String mode; // 'uint32' or 'string'
  late final Uint8List _buffer;
  late final ByteData _byteData;

  PasswordBuffer(this.nonce, {this.mode = 'uint32'}) {
    _buffer = Uint8List(nonce.length + _counterBytes);
    _buffer.setAll(0, nonce);
    _byteData = ByteData.view(_buffer.buffer);
  }

  /// Returns a buffer containing nonce + encoded counter.
  ///
  /// In 'string' mode the counter is UTF-8 encoded.
  /// In 'uint32' mode the counter is a big-endian 32-bit integer.
  Uint8List setCounter(int n) {
    if (mode == 'string') {
      return concatBuffers(nonce, utf8.encode(n.toString()));
    }
    _byteData.setUint32(nonce.length, n, Endian.big);
    return _buffer;
  }
}
