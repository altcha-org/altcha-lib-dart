import 'types.dart';
import 'pow.dart';

/// WASM/web fallback: runs single-threaded since [dart:isolate] is unavailable.
Future<Solution?> solveChallengeIsolates({
  required Challenge challenge,
  required DeriveKeyFunction deriveKey,
  int concurrency = 1,
  CounterMode counterMode = CounterMode.uint32,
  Duration timeout = const Duration(seconds: 90),
}) {
  return solveChallenge(
    challenge: challenge,
    deriveKey: deriveKey,
    counterMode: counterMode,
    timeout: timeout,
  );
}
