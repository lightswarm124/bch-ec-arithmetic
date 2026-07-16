# EC opcode proposal comparison

This document maps the executable benchmark to the two primary proposal
operations and the three addendum operations described in
[TECHNICAL_ADDENDUM.md](../TECHNICAL_ADDENDUM.md).

## Operation mapping

| Operation | Operand harness | Emulated implementation | Evidence |
| --- | --- | --- | --- |
| `OP_ECADD` | `benchmarks/cashscript/contracts/functions.cash`, `simulateEcadd` | `pointAdd`, Jacobian add, and mixed-add in `ec-emulation.cash` | Directly exercised by DLEQ, Pedersen, and Bulletproof workloads |
| `OP_ECMUL` | `simulateEcmul` | `scalarMultiply` and `doubleScalarMultiply` | Dominant cost in full-width scalar workloads |
| `OP_MODINV` | `simulateModinv` | `modInverse` and affine conversion; Bulletproof inversions | Extended-Euclidean inversion is expensive in integer-only CashScript |
| `OP_ECMULTGEN` | `simulateEcmultgen` | Fixed-generator scalar multiplication | Maps naturally to Schnorr and Pedersen generator terms |
| `OP_ECMULTMULTI` | `simulateEcmultmulti` | Double-scalar and batched DLEQ multiplication | Relevant to MSM-style verification; batched emulation remained 174 over |

The minimal operand harness validates widths and point shapes but does not
calculate EC results. It is an ABI/validation-shape test, not a native-opcode
simulation. The full emulation contracts calculate and verify the results;
those contracts provide the VM cost data.

## Primary proposal conclusion

`OP_ECADD` and `OP_ECMUL` are the direct comparison for these experiments.
Full-width DLEQ, Pedersen, and Bulletproof verification repeatedly performs
the same operations that the primary proposal would make native on
secp256k1. The results establish the cost of doing that work generically in
CashScript.

There is no native-opcode measurement in this repository yet because the
installed CashScript/VM environment does not expose the proposed operations.
The proposal should use a future native implementation for the A/B operation
cost comparison rather than a projected number.

## Addendum conclusion

The addendum operations address distinct bottlenecks:

- `OP_MODINV` targets inversion in affine EC conversion and Bulletproof
  verification. Its exact benefit depends on the modulus and opcode semantics.
- `OP_ECMULTGEN` specializes fixed-generator multiplication for Schnorr and
  Pedersen-style terms.
- `OP_ECMULTMULTI` reduces repeated scalar multiplication and is the closest
  addendum operation to multi-scalar DLEQ/Bulletproof work.

The batched DLEQ result is an important caution: an algebraically shared
formula does not automatically produce a cheaper BCH script. Script length
also affects the density allowance, so saving instructions can reduce the
available budget as well.

## Groth16 context

Groth16 is relevant as a VM-architecture example. The current public BCH
result, as observed on 2026-07-16, is an 86,950-byte total on-chain score for
a BN254 verifier split across 11 inputs. That number is total serialized
on-chain size—not a per-input op-cost number. Each sub-program is reported as
within the current per-input limits, and the construction fits in one
standard transaction. A smaller one-input verifier exists, but exceeds
current compute limits. See [verifier.cash](https://www.verifier.cash/) and
the [benchmark harness](https://github.com/mr-zwets/zk-verifier-bench).

It is not a direct benchmark for the proposed secp256k1 operations:

1. These experiments use secp256k1. The published Groth16 result uses BN254,
   with BLS12-381 also represented in the benchmark.
2. Native secp256k1 ECADD/ECMUL/ECMULTGEN/ECMULTMULTI would not directly
   execute BN254 point operations.
3. Groth16's major remaining workload is pairing verification and extension
   field arithmetic (`Fp2`, `Fp6`, and `Fp12`), not only ordinary secp256k1
   point operations.

Therefore Groth16 supports the case for multi-input computation and careful
VM accounting, but it should not be presented as evidence that the current
secp256k1 opcode proposal alone implements a Groth16 verifier. A future
pairing-friendly-curve or field-arithmetic proposal would be needed for that
direct connection.

## Claims supported by this benchmark

The benchmark supports these claims:

- user-defined CashScript functions can express and invoke reusable helpers;
- secp256k1 EC arithmetic can be emulated with user-supplied operands;
- full-width DLEQ, Pedersen range-proof, and Bulletproof equations can be
  checked off-chain and measured in the BCH VM;
- each full-width path exceeds current per-input limits;
- bounded DLEQ and Pedersen demonstrations passed Mocknet and CHIPNET;
- native EC/scalar operations are the meaningful next comparison.

It does not claim that bounded contracts are production-secure, that the
full-width emulated proofs fit BCH today, that the proposed native opcodes
have been benchmarked, or that this repository reproduced the published
Groth16 result.
