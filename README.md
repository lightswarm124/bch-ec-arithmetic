# CHIP-2025-05: Native Elliptic Curve Arithmetic Operations

```
Title: Native Elliptic Curve Arithmetic Operations
Type: Standards
Layer: Consensus
Maintainer: Jerry Qian (lightswarm)
Status: Draft
Initial Publication Date: 2025-05-23
Latest Revision Date: 2026-07-06
Version: 0.2.0
```

## Abstract

This CHIP defines two consensus opcodes for native secp256k1 affine elliptic-curve arithmetic in BCH locking scripts:

- `OP_ECADD`
- `OP_ECMUL`

The purpose of these opcodes is to provide the elliptic-curve arithmetic needed for locking-script validation and other developer-defined protocols, while keeping the scope small enough to specify, implement, benchmark, and audit.

## Motivation

The thread converged on a practical need, not just a general desire for more math:

- BCH locking scripts need point addition and scalar multiplication to validate EC relationships directly
- proof-carrying protocols, aggregate signatures, covenant logic, and custom cryptographic protocols benefit from native curve operations
- emulation in script is possible but far too expensive for real-world use

The discussion also made two requirements clear:

- the CHIP needs a real, concrete locking-script use case, not just toy examples
- the initial spec should stay focused instead of expanding into a large math package

## Scope

### In scope

- affine point addition on secp256k1
- affine scalar multiplication on secp256k1
- deterministic failure on invalid inputs
- fixed-width 32-byte big-endian encodings

### Out of scope

The following are intentionally not included in this CHIP:

- modular inversion
- point negation
- point doubling as a separate opcode
- point decompression
- multi-scalar multiplication
- pairings
- generic curve selection
- masked transfer balances or transaction-value confidentiality

These can be proposed later if there is a separate use case and implementation budget.

This proposal does not change transaction format or output visibility. It only adds EC math to locking-script evaluation.

## Review Assets

- [Logical fixtures](./fixtures/README.md) cover canonical operand semantics for the core CHIP and follow-on candidates.
- [VM fixtures](./fixtures/vm/README.md) cover bytecode-level consensus behavior for `OP_ECADD` and `OP_ECMUL`.
- [Technical addendum](./TECHNICAL_ADDENDUM.md) sketches candidate follow-on opcodes and remaining design questions.
- [package.json](./package.json) and the lockfile make `npm install` and `npm run validate` fully turnkey.

## Definitions

The curve is secp256k1 over the field `F_p` where:

- `p = 2^256 - 2^32 - 977`
- `n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
- `G` is the standard secp256k1 generator

A point is represented in affine coordinates as `(x, y)` using 32-byte big-endian integers.

### Canonical encoding

All field elements and scalars MUST be encoded as exactly 32 bytes.

- Field elements MUST satisfy `0 <= value < p`
- Scalars MUST satisfy `1 <= value < n`

There is no compressed-point representation in this CHIP.

### Stack notation

Stack items are listed top-to-bottom.

If an opcode pops `A`, then `B`, `A` is the topmost item.

## Opcode Semantics

### `OP_ECADD`

#### Inputs

Top-to-bottom stack inputs:

- `pointB_y`
- `pointB_x`
- `pointA_y`
- `pointA_x`

#### Behavior

1. Parse all four inputs as canonical 32-byte big-endian field elements.
2. Fail if any input is not canonical or is greater than or equal to `p`.
3. Interpret the inputs as affine secp256k1 points `A = (pointA_x, pointA_y)` and `B = (pointB_x, pointB_y)`.
4. Fail if either point is not on the secp256k1 curve.
5. Compute `R = A + B` in the secp256k1 group.
6. Fail if `R` is the point at infinity.
7. Push the result coordinates back onto the stack.

#### Outputs

Top-to-bottom stack outputs:

- `result_y`
- `result_x`

### `OP_ECMUL`

#### Inputs

Top-to-bottom stack inputs:

- `scalar`
- `point_y`
- `point_x`

#### Behavior

1. Parse `scalar` as a canonical 32-byte big-endian integer.
2. Fail if `scalar` is not canonical or is not in the range `1 <= scalar < n`.
3. Parse `point_x` and `point_y` as canonical 32-byte big-endian field elements.
4. Fail if the point is not on the secp256k1 curve.
5. Compute `R = scalar * point`.
6. Fail if `R` is the point at infinity.
7. Push the result coordinates back onto the stack.

#### Outputs

Top-to-bottom stack outputs:

- `result_y`
- `result_x`

## Consensus Rules

The following are consensus-critical:

- All implementations MUST use the same curve parameters and canonical encodings.
- Any invalid input MUST fail the opcode atomically.
- A failure MUST leave no partial outputs on the stack.
- The output of each opcode MUST be deterministic for the same input bytes.
- Points at infinity are not representable as successful results in this CHIP.

Implementations MAY use projective or Jacobian coordinates internally, but the consensus result MUST match the affine semantics above.

## Resource Accounting

Native EC arithmetic is expensive enough that it MUST be explicitly metered.

- `OP_ECADD` MUST charge a fixed consensus operation cost.
- `OP_ECMUL` MUST charge a fixed consensus operation cost.
- Both costs MUST be enforced by the VM op-cost limit.
- The exact cost constants SHOULD be benchmarked against a reference implementation before activation.
- `OP_ECMUL` MUST cost at least as much as `OP_ECADD`.

If the chosen op-cost budget cannot support these operations safely, the CHIP should not activate.

## Security Considerations

### DoS resistance

The opcodes must be bounded by the VM cost meter so they cannot be used to create unbounded work.

### Input validation

Consensus must reject:

- malformed 32-byte encodings
- field elements outside the secp256k1 field
- scalars outside the secp256k1 scalar range
- points not on the curve
- operations that would produce the point at infinity

### Implementation safety

Reference code SHOULD use constant-time routines where practical.

That is an implementation requirement, not a consensus requirement, but it matters because these operations are cryptographic primitives and will likely be used in sensitive locking-script logic.

### Scope control

The thread made clear that scope creep is a real risk. Keeping the first CHIP to `ECADD` and `ECMUL` avoids mixing the base primitive with more specialized operations that deserve separate analysis.

## Reference Use Cases

The thread identified the first concrete use cases that justify the CHIP:

- EC commitment validation and covenant authorization logic
- MuSig-style aggregation and related threshold signing workflows
- proof-carrying locking-script protocols and other developer-defined script logic
- future SNARK/STARK-style locking-script components

At least one end-to-end locking-script example SHOULD accompany the final CHIP submission so the network can evaluate a real BCH transaction use case, not just a toy example.

## Test Vectors

The implementation test suite SHOULD include:

- `scalar = 2`, `point = G`, expect `2G`
- `pointA = G`, `pointB = 2G`, expect `3G`
- invalid point `(0x01, 0x01)`, expect failure
- `scalar = 0`, expect failure
- `scalar = n`, expect failure
- `pointA = G`, `pointB = -G`, expect failure because the result is infinity

See [fixtures/README.md](./fixtures/README.md) for machine-readable fixture sets covering the core CHIP and the addendum opcodes.

Those fixtures intentionally include boundary-value and failure cases for canonical encoding, invalid points, infinity, and multi-scalar count mismatches so implementers can exercise the consensus failure paths, not just the happy path.

See [fixtures/vm/README.md](./fixtures/vm/README.md) for raw-bytecode execution fixtures that cover stack underflow, malformed pushes, and atomic failure behavior in the BCH VM.

Test vectors SHOULD be checked against a known-good secp256k1 implementation such as libsecp256k1.

## Deployment

Deployment details remain TODO.

The open items that should be resolved before activation are:

- final opcode numbering or opcode-family encoding
- exact op-cost constants
- reference implementation benchmark results
- a real locking-script example or covenant demonstrating practical utility

### Current BCHN Opcode Window

BCHN currently leaves the `0xbd`-`0xbf` window unassigned, and this proposal leaves those bytes untouched for other future work. For the EC proposal itself, the usable reserve space starts at `0xd6` and is split by BCHN's `0xef` token prefix:

- `0xd6`-`0xee`
- `0xf0`-`0xfe`

`0xef` is not a normal candidate because BCHN uses it as `SPECIAL_TOKEN_PREFIX`, and `0xff` is `INVALIDOPCODE`. That means the practical reserve region is `0xd6`-`0xee` and `0xf0`-`0xfe`, with `0xef` excluded.

### Opcode Family Proposal

One forum proposal suggests reserving a single opcode prefix for EC arithmetic, with the selector carried as script data rather than as a multi-byte opcode. BCHN's current opcode map already uses `0xbc` for `OP_REVERSEBYTES`, so `0xbc` is not available for this purpose. For this proposal, the first EC bytes should start at `0xd6` so that `0xbd`-`0xbf` remain available for unrelated future proposals:

- `0xd6` = `OP_ECADD`
- `0xd7` = `OP_ECMUL`
- `0xd8` = possible reserved follow-on slot or EC-family prefix
- `0xd9`-`0xde` = possible follow-on EC bytes
- `0xdf`-`0xee` = additional reserve space
- `0xf0`-`0xfe` = additional reserve space

The benefit is opcode-surface conservation: future EC primitives can be added without burning a new top-level opcode every time. The tradeoff is that a family design would need a concrete selector encoding and dispatch rule, because the opcode bytes themselves are still only one byte wide. This is the most practical way to preserve room for future curve families, including any later post-quantum replacement for secp256k1, while keeping the reserve bytes explicitly aligned to BCHN's current map.

These reserved bytes matter because the loop and function opcodes can make an emulation readable, but they do not change the arithmetic cost class. In practice, `OP_DEFINE`/`OP_INVOKE` and `OP_BEGIN`/`OP_UNTIL` only restructure the work that `ECADD`, `ECMUL`, and the addendum opcodes would otherwise remove.

## Future Work

These opcodes are being explored as potential additions to this CHIP:

- `OP_MODINV`
- `OP_ECMULTGEN`
- `OP_ECMULTMULTI`
- pairing-based protocol support

This is actively being discussed in [Bitcoin Cash Research thread](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570/14)

## Technical Addendum

See [TECHNICAL_ADDENDUM.md](./TECHNICAL_ADDENDUM.md) for candidate follow-on opcodes, their intended use cases, and a detailed sketch of how each one would be specified.

## References

- [secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
- [Bitcoin Cash Research thread](https://bitcoincashresearch.org/t/chip-2025-05-native-elliptic-curve-arithmetic-operations/1570)
- [CHIP-2021-05 VM Limits](https://github.com/bitjson/bch-vm-limits)
- [Bitcoin Wiki: ECDSA](https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)

## Copyright

This document is placed in the public domain.
