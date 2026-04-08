// Basic HTTP server example demonstrating ALTCHA PoW v2 integration.
// Endpoints:
//   GET  /challenge  - issues a new signed PoW challenge
//   POST /submit     - validates a form submission containing an ALTCHA payload
// Run:
//   dart run example/http_server.dart

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:altcha_lib/altcha_lib.dart';
import 'package:altcha_lib/src/algorithms/pbkdf2.dart' as pbkdf2;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const _hmacSecret = 'change-me-in-production';
const _hmacKeySecret = 'change-me-in-production';
const _host = 'localhost';
const _port = 3000;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

Future<void> main() async {
  final server = await HttpServer.bind(_host, _port);
  print('Listening on http://$_host:$_port');

  await for (final request in server) {
    _handleRequest(request);
  }
}

// ---------------------------------------------------------------------------
// Request dispatcher
// ---------------------------------------------------------------------------

Future<void> _handleRequest(HttpRequest request) async {
  // Add CORS headers to every response.
  _addCorsHeaders(request.response);

  // Handle pre-flight OPTIONS requests.
  if (request.method == 'OPTIONS') {
    request.response
      ..statusCode = HttpStatus.noContent
      ..close();
    return;
  }

  try {
    if (request.method == 'GET' && request.uri.path == '/challenge') {
      await _getChallenge(request);
    } else if (request.method == 'POST' && request.uri.path == '/submit') {
      await _postSubmit(request);
    } else {
      _sendJson(request.response, HttpStatus.notFound,
          {'error': 'Not found'});
    }
  } catch (e, st) {
    stderr.writeln('Unhandled error: $e\n$st');
    _sendJson(request.response, HttpStatus.internalServerError,
        {'error': 'Internal server error'});
  }
}

// ---------------------------------------------------------------------------
// GET /challenge
// ---------------------------------------------------------------------------

Future<void> _getChallenge(HttpRequest request) async {
  final challenge = await createChallenge(
    algorithm: 'PBKDF2/SHA-256',
    cost: 5000,
    counter: 5000 + Random.secure().nextInt(5000),
    deriveKey: pbkdf2.deriveKey,
    hmacSignatureSecret: _hmacSecret,
    hmacKeySignatureSecret: _hmacKeySecret,
    expiresAt: DateTime.now().add(Duration(minutes: 10)),
  );

  _sendJson(request.response, HttpStatus.ok, challenge.toJson());
}

// ---------------------------------------------------------------------------
// POST /submit
// ---------------------------------------------------------------------------

Future<void> _postSubmit(HttpRequest request) async {
  // Parse application/x-www-form-urlencoded body.
  final body = await _readBody(request);
  final data = Uri.splitQueryString(body);

  // Extract and decode the ALTCHA payload.
  final altchaRaw = data['altcha'];
  if (altchaRaw == null || altchaRaw.isEmpty) {
    _sendJson(request.response, HttpStatus.badRequest,
        {'error': 'Missing altcha field'});
    return;
  }

  final Payload payload;
  try {
    final decoded = jsonDecode(utf8.decode(base64Decode(altchaRaw)));
    payload = Payload.fromJson(decoded as Map<String, dynamic>);
  } catch (_) {
    _sendJson(request.response, HttpStatus.badRequest,
        {'error': 'Invalid altcha payload'});
    return;
  }

  // Verify the PoW solution.
  final result = await verifySolution(
    challenge: payload.challenge,
    solution: payload.solution,
    deriveKey: pbkdf2.deriveKey,
    hmacSignatureSecret: _hmacSecret,
    hmacKeySignatureSecret: _hmacKeySecret,
  );

  if (!result.verified) {
    final reason = result.expired
        ? 'Challenge expired'
        : result.invalidSignature == true
            ? 'Invalid challenge signature'
            : 'Invalid solution';
    _sendJson(request.response, HttpStatus.unprocessableEntity,
        {'error': reason});
    return;
  }

  _sendJson(request.response, HttpStatus.ok, {
    'success': true,
    'altcha': result.toJson(),
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void _addCorsHeaders(HttpResponse response) {
  response.headers
    ..set('Access-Control-Allow-Origin', '*')
    ..set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    ..set('Access-Control-Allow-Headers', 'Content-Type');
}

void _sendJson(HttpResponse response, int status, Map<String, dynamic> body) {
  final encoded = jsonEncode(body);
  response
    ..statusCode = status
    ..headers.contentType = ContentType.json
    ..write(encoded)
    ..close();
}

Future<String> _readBody(HttpRequest request) async {
  final buffer = StringBuffer();
  await for (final chunk
      in request.cast<List<int>>().transform(utf8.decoder)) {
    buffer.write(chunk);
  }
  return buffer.toString();
}
