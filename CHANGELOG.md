## 0.4.0

- Fix web compatibility issues

## 0.2.0

- The PBKDF2 algorithm now uses `crypto` for improved performance
- Added `adaptiveDeriveKey` with automatic algorithm detection

## 0.1.1

- Upgraded `pointycastle` to `^4.0.0`.
- Removed `argon2` dependency; Argon2id now uses pointycastle's built-in implementation.
- Upgraded `lints` to `^6.1.0`.

## 0.1.0

- Initial release.
- `createChallenge` — create signed PoW v2 challenges with optional deterministic mode.
- `solveChallenge` — brute-force solve a challenge on the current isolate.
- `solveChallengeIsolates` — parallel solver using multiple Dart isolates.
- `verifySolution` — verify a client-submitted solution.
- `verifyServerSignature` — verify an ALTCHA Sentinel server signature payload.
- `verifyFieldsHash` — verify a hash of submitted form fields.
- Algorithm support: PBKDF2/SHA-256, PBKDF2/SHA-384, PBKDF2/SHA-512, SHA-256, SHA-384, SHA-512, Scrypt, Argon2id.
