## 1.0.0

- Fix challenge signatures for `data` with unsorted keys or `null` values: `createChallenge` and `verifySolution` now both sign altcha-lib's canonical JSON (keys sorted recursively, nulls kept). Before this fix, such challenges never verified, in Dart or in JS.
- `ChallengeParameters.toSortedJson()` now sorts nested map keys too.
- `verifySolution` now returns `invalidSolution` instead of throwing when `solution.derivedKey` is not valid even-length hex on the key-signature path.
- `verifySolution` now compares an even-length `keyPrefix` as bytes, like `solveChallenge` and altcha-lib, so uppercase hex prefixes verify.
- `verifySolution` expiry now matches altcha-lib: `expiresAt` is compared against the current time in fractional seconds (no up-to-1 s grace), and `expiresAt: 0` means no expiry.
- Empty-string secrets are now treated as unset, as in altcha-lib: `createChallenge` with `hmacSignatureSecret: ''` returns an unsigned challenge, `hmacKeySignatureSecret: ''` adds no `keySignature` and makes `verifySolution` re-derive the key, and `verifySolution` with `hmacSignatureSecret: ''` returns `invalidSignature` (previously any challenge HMAC'd under the empty key verified). Likewise, `verifyServerSignature` with `hmacSecret: ''` returns `invalidSignature`, and `signChallenge` with `hmacSignatureSecret: ''` throws `ArgumentError`.
- `solveChallenge` and `solveChallengeIsolates` now treat `timeout: Duration.zero` as no timeout, as in altcha-lib (previously it returned `null` immediately). `solveChallengeIsolates` also no longer truncates sub-millisecond timeouts to zero.
- Unknown challenge parameters are now preserved, as in altcha-lib: `ChallengeParameters.extra` holds keys not modelled as fields, `fromJson` fills it and `toJson` emits it, so they are signed and verified (keys in `extra` that name a modelled field are ignored). `createChallenge` merges every key returned by `deriveKey` (like `Object.assign`), not just a fixed subset.
- **Breaking:** `ChallengeParameters.expiresAt` is now `num?` (was `int?`), and `createChallenge(expiresAt:)` accepts any `num`, so fractional `expiresAt` values from altcha-lib parse and verify instead of throwing.
- `canonicalJson` now formats numbers like `JSON.stringify`: integral doubles have no `.0` (`1.0` → `1`) and `-0.0` is `0`, so challenges whose `data` holds such doubles verify across implementations.
- `canonicalJson` now orders keys exactly as altcha-lib's `JSON.stringify(sortKeys(...))`: integer-like keys (`"0"`…`"4294967294"`) come first in numeric order, then the remaining keys sorted, and a `__proto__` key is dropped. Previously, challenges whose `data` had integer-like keys (e.g. `{'9': …, '10': …}`) failed signature verification across implementations.
- `verifyServerSignature` no longer throws when `verificationData` has a non-integer `expire` (e.g. `1.5`, `abc`, empty); such input was client-controlled and crashed the call even for forged payloads. `expire` is now evaluated like altcha-lib: `0` or empty means no expiry, fractional values are compared as numbers.

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
