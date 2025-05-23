# CHIP-2025-05: Native Elliptic Curve Arithmetic Operations

```
    Title: Native Elliptic Curve Arithmetic Operations
    Type: Standards
    Layer: Consensus
    Maintainer: TBD
    Status: Draft
    Initial Publication Date: 2025-05-23
    Latest Revision Date: 2025-05-23
    Version: 0.1.0
```

## Summary

This CHIP proposes two new Bitcoin Cash VM opcodes:

* `OP_ECADD`: Perform an elliptic curve point addition
* `OP_ECMUL`: Perform an elliptic curve scalar multiplication

These operations are defined over the secp256k1 elliptic curve and mirror the underlying cryptographic operations used in Bitcoin’s signature scheme.

## Motivation

Currently, Bitcoin Cash smart contracts do not support native elliptic curve arithmetic, limiting advanced cryptographic applications like:

* Zero-knowledge proof verification (e.g., Bulletproofs, Halo)
* Threshold signatures and MuSig-style key aggregation
* Verifiable delay functions (VDFs)
* Identity-based encryption

Instead, these must be emulated inefficiently using hash-based constructions or precomputed lookup tables. This significantly increases contract bytecode length, execution cost, and verification time. Native opcodes reduce complexity and bring BCH contract capabilities on par with or beyond those of other programmable blockchains.

## Technical Specification

### `OP_ECADD`

**Codepoint**: TBD (proposed: `0xe0`)

**Stack inputs**:

* `[pointB_y]` (bytes, 32 bytes)
* `[pointB_x]` (bytes, 32 bytes)
* `[pointA_y]` (bytes, 32 bytes)
* `[pointA_x]` (bytes, 32 bytes)

**Stack output**:

* `[result_y]` (bytes, 32 bytes)
* `[result_x]` (bytes, 32 bytes)

**Semantics**:

* Validates that `pointA` and `pointB` are on the secp256k1 curve.
* Computes `result = pointA + pointB` using elliptic curve addition.
* Pushes the `x` and `y` coordinates of the resulting point onto the stack.
* If either input is not a valid curve point, the operation fails.

### `OP_ECMUL`

**Codepoint**: TBD (proposed: `0xe1`)

**Stack inputs**:

* `[scalar]` (bytes, 32 bytes)
* `[point_y]` (bytes, 32 bytes)
* `[point_x]` (bytes, 32 bytes)

**Stack output**:

* `[result_y]` (bytes, 32 bytes)
* `[result_x]` (bytes, 32 bytes)

**Semantics**:

* Validates that `point` is on the secp256k1 curve.
* Computes `result = scalar * point` using elliptic curve scalar multiplication.
* Pushes the `x` and `y` coordinates of the resulting point.
* If the scalar is zero or the input point is not valid, fails.

## Security Considerations

### Consensus Stability

These operations must be implemented identically across all consensus-enforcing nodes. Care must be taken to use constant-time implementations to prevent side-channel attacks. Additionally:

* Inputs must be strictly validated to lie on the secp256k1 curve.
* Points at infinity must be handled deterministically (e.g., operation fails).
* Inputs must be of fixed size (32 bytes each), or the transaction is invalid.

### Denial-of-Service (DoS) Prevention

Native EC arithmetic is computationally expensive. To prevent DoS:

* Each call to `OP_ECADD` or `OP_ECMUL` will carry a high operation cost (proposed: 20,000 and 100,000 respectively).
* Cumulative cost will be tracked using the existing Operation Cost Limit from the [VM Limits CHIP](https://github.com/bitjson/bch-vm-limits).

### Precedent

Many chains such as Ethereum (via precompiles), Zcash, and Starknet support native elliptic curve operations. However, BCH's model allows deterministic, stateless validation — these operations fit well with that design when bounded by operation cost.

## Implementation Notes

* Leverage existing open-source libraries (e.g., libsecp256k1) in C++ implementations.
* Validate against test vectors defined below.
* Enforce minimal encoding of inputs as 32-byte big-endian integers.

## Test Vectors

```text
// Scalar multiplication
Input:
  scalar = 0x02
  point = G (secp256k1 generator point)
Output:
  result = 2G (verify against known coordinates)

// Point addition
Input:
  pointA = G
  pointB = 2G
Output:
  result = 3G (verify against known coordinates)

// Invalid point
Input:
  point = (0x01, 0x01) // Not on curve
Result:
  VM Error
```

## Deployment

Target upgrade: May 2027

* Chipnet activation MTP: TBD (\~Nov 2026)
* Mainnet activation MTP: TBD (\~May 2027)

## Future Work

This CHIP enables more advanced constructions:

* Ring signatures
* Bulletproofs / Halo / PLONK ZKPs
* MuSig-style contract aggregation
* General SNARK/STARK verification

It also enables BCH-native zero-knowledge systems and privacy protocols without emulating arithmetic through hashes.

## References

* [secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
* [CHIP-2021-05 VM Limits](https://github.com/bitjson/bch-vm-limits)
* [Ethereum Yellow Paper: Precompiled Contracts](https://ethereum.github.io/yellowpaper/paper.pdf)
* [Zcash: Sapling Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)

## Copyright

This document is placed in the public domain.
