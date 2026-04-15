import 'dart:async';
import 'dart:isolate';

import 'types.dart';
import 'pow.dart';

typedef _IsolateArgs = ({
  Map<String, dynamic> challengeJson,
  DeriveKeyFunction deriveKey,
  int counterStart,
  int counterStep,
  String counterModeStr,
  int timeoutMs,
  SendPort sendPort,
});

/// Solves a challenge using multiple [Isolate]s in parallel.
///
/// Each isolate tests an interleaved subset of counter values
/// (isolate `i` starts at `i` and steps by [concurrency]).
/// The first isolate to find a solution wins; all others are killed immediately.
///
/// [deriveKey] must be a top-level or static function — closures cannot
/// be sent across isolate boundaries.
Future<Solution?> solveChallengeIsolates({
  required Challenge challenge,
  required DeriveKeyFunction deriveKey,
  int concurrency = 1,
  CounterMode counterMode = CounterMode.uint32,
  Duration timeout = const Duration(seconds: 90),
}) async {
  final workerCount = concurrency.clamp(1, 16);
  final receivePort = ReceivePort();
  final isolates = <Isolate>[];

  try {
    for (var i = 0; i < workerCount; i++) {
      isolates.add(await Isolate.spawn<_IsolateArgs>(
        _isolateWorker,
        (
          challengeJson: challenge.toJson(),
          deriveKey: deriveKey,
          counterStart: i,
          counterStep: workerCount,
          counterModeStr: counterMode == CounterMode.string ? 'string' : 'uint32',
          timeoutMs: timeout.inMilliseconds,
          sendPort: receivePort.sendPort,
        ),
      ));
    }

    Solution? solution;
    var pending = workerCount;

    await for (final msg in receivePort) {
      pending--;
      if (msg is Map<String, dynamic> && solution == null) {
        solution = Solution.fromJson(msg);
      }
      if (solution != null || pending == 0) break;
    }

    return solution;
  } finally {
    for (final iso in isolates) {
      iso.kill(priority: Isolate.immediate);
    }
    receivePort.close();
  }
}

Future<void> _isolateWorker(_IsolateArgs args) async {
  final challenge = Challenge.fromJson(args.challengeJson);
  final counterMode =
      args.counterModeStr == 'string' ? CounterMode.string : CounterMode.uint32;
  final solution = await solveChallenge(
    challenge: challenge,
    deriveKey: args.deriveKey,
    counterStart: args.counterStart,
    counterStep: args.counterStep,
    counterMode: counterMode,
    timeout: Duration(milliseconds: args.timeoutMs),
  );
  args.sendPort.send(solution?.toJson());
}
