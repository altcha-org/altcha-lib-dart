/// Supported HMAC digest algorithms.
enum HmacAlgorithm {
  sha256('SHA-256'),
  sha384('SHA-384'),
  sha512('SHA-512');

  final String value;
  const HmacAlgorithm(this.value);

  static HmacAlgorithm fromString(String value) {
    return HmacAlgorithm.values.firstWhere(
      (a) => a.value == value,
      orElse: () => HmacAlgorithm.sha256,
    );
  }
}

/// Parameters embedded in a challenge.
class ChallengeParameters {
  final String algorithm;
  final String nonce;
  final String salt;
  final int cost;
  final int keyLength;
  String keyPrefix;
  String? keySignature;
  final int? memoryCost;
  final int? parallelism;
  final int? expiresAt;
  final Map<String, Object?>? data;

  ChallengeParameters({
    required this.algorithm,
    required this.nonce,
    required this.salt,
    required this.cost,
    required this.keyLength,
    required this.keyPrefix,
    this.keySignature,
    this.memoryCost,
    this.parallelism,
    this.expiresAt,
    this.data,
  });

  factory ChallengeParameters.fromJson(Map<String, dynamic> json) {
    return ChallengeParameters(
      algorithm: json['algorithm'] as String,
      nonce: json['nonce'] as String,
      salt: json['salt'] as String,
      cost: json['cost'] as int,
      keyLength: json['keyLength'] as int,
      keyPrefix: json['keyPrefix'] as String,
      keySignature: json['keySignature'] as String?,
      memoryCost: json['memoryCost'] as int?,
      parallelism: json['parallelism'] as int?,
      expiresAt: json['expiresAt'] as int?,
      data: json['data'] == null
          ? null
          : Map<String, Object?>.from(json['data'] as Map),
    );
  }

  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{
      'algorithm': algorithm,
      'cost': cost,
      'keyLength': keyLength,
      'keyPrefix': keyPrefix,
      'nonce': nonce,
      'salt': salt,
    };
    if (data != null) map['data'] = data;
    if (expiresAt != null) map['expiresAt'] = expiresAt;
    if (keySignature != null) map['keySignature'] = keySignature;
    if (memoryCost != null) map['memoryCost'] = memoryCost;
    if (parallelism != null) map['parallelism'] = parallelism;
    return map;
  }

  /// Returns a new map with keys sorted alphabetically (for canonical JSON).
  Map<String, dynamic> toSortedJson() {
    final json = toJson();
    final sorted = Map.fromEntries(
      json.entries.toList()..sort((a, b) => a.key.compareTo(b.key)),
    );
    return sorted;
  }

  ChallengeParameters copyWith({
    String? keyPrefix,
    String? keySignature,
  }) {
    return ChallengeParameters(
      algorithm: algorithm,
      nonce: nonce,
      salt: salt,
      cost: cost,
      keyLength: keyLength,
      keyPrefix: keyPrefix ?? this.keyPrefix,
      keySignature: keySignature ?? this.keySignature,
      memoryCost: memoryCost,
      parallelism: parallelism,
      expiresAt: expiresAt,
      data: data,
    );
  }
}

/// A PoW challenge returned by [createChallenge].
class Challenge {
  final ChallengeParameters parameters;
  final String? signature;

  Challenge({required this.parameters, this.signature});

  factory Challenge.fromJson(Map<String, dynamic> json) {
    return Challenge(
      parameters: ChallengeParameters.fromJson(
        json['parameters'] as Map<String, dynamic>,
      ),
      signature: json['signature'] as String?,
    );
  }

  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{
      'parameters': parameters.toSortedJson(),
    };
    if (signature != null) map['signature'] = signature;
    return map;
  }
}

/// A solution produced by [solveChallenge].
class Solution {
  final int counter;
  final String derivedKey;
  final double? time;

  Solution({required this.counter, required this.derivedKey, this.time});

  factory Solution.fromJson(Map<String, dynamic> json) {
    return Solution(
      counter: json['counter'] as int,
      derivedKey: json['derivedKey'] as String,
      time: (json['time'] as num?)?.toDouble(),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'counter': counter,
      'derivedKey': derivedKey,
      if (time != null) 'time': time,
    };
  }
}

/// Result returned by [verifySolution].
class VerifySolutionResult {
  final bool expired;
  final bool? invalidSignature;
  final bool? invalidSolution;
  final double time;
  final bool verified;

  VerifySolutionResult({
    required this.expired,
    required this.invalidSignature,
    required this.invalidSolution,
    required this.time,
    required this.verified,
  });

  Map<String, dynamic> toJson() => {
        'expired': expired,
        'invalidSignature': invalidSignature,
        'invalidSolution': invalidSolution,
        'time': time,
        'verified': verified,
      };
}

/// Result returned by [verifyServerSignature].
class VerifyServerSignatureResult extends VerifySolutionResult {
  final Map<String, dynamic>? verificationData;

  VerifyServerSignatureResult({
    required super.expired,
    required super.invalidSignature,
    required super.invalidSolution,
    required super.time,
    required super.verified,
    this.verificationData,
  });

  @override
  Map<String, dynamic> toJson() => {
        ...super.toJson(),
        if (verificationData != null) 'verificationData': verificationData,
      };
}

/// Payload submitted by the client widget.
class Payload {
  final Challenge challenge;
  final Solution solution;

  Payload({required this.challenge, required this.solution});

  factory Payload.fromJson(Map<String, dynamic> json) {
    return Payload(
      challenge: Challenge.fromJson(json['challenge'] as Map<String, dynamic>),
      solution: Solution.fromJson(json['solution'] as Map<String, dynamic>),
    );
  }
}

/// Server-issued signature payload (ALTCHA API).
class ServerSignaturePayload {
  final String algorithm;
  final String? apiKey;
  final String? id;
  final String signature;
  final String verificationData;
  final bool verified;

  ServerSignaturePayload({
    required this.algorithm,
    this.apiKey,
    this.id,
    required this.signature,
    required this.verificationData,
    required this.verified,
  });

  factory ServerSignaturePayload.fromJson(Map<String, dynamic> json) {
    return ServerSignaturePayload(
      algorithm: json['algorithm'] as String,
      apiKey: json['apiKey'] as String?,
      id: json['id'] as String?,
      signature: json['signature'] as String,
      verificationData: json['verificationData'] as String,
      verified: json['verified'] as bool,
    );
  }
}

/// Counter encoding mode.
enum CounterMode {
  uint32,
  string,
}

/// Function that derives a key given challenge parameters, salt, and password.
typedef DeriveKeyFunction = Future<DeriveKeyResult> Function(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
);

/// Result returned by a [DeriveKeyFunction].
class DeriveKeyResult {
  final List<int> derivedKey;
  final Map<String, dynamic>? parameters;

  DeriveKeyResult({required this.derivedKey, this.parameters});
}
