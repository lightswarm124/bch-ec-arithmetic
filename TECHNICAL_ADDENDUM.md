# Technical Addendum: Additional EC Math Opcodes

This addendum collects the follow-on opcodes that are still plausibly worth standardizing after `OP_ECADD` and `OP_ECMUL`.

Several of these ideas are being explored by other teams as well. The point here is to keep only the primitives that materially expand capability or save orders of magnitude in script cost.

The purpose is not to standardize all of these in one step. The purpose is to define the most plausible next primitives precisely enough that the CHIP can explain:

- what each opcode would be used for
- what the consensus surface looks like
- how to bound the implementation and VM cost
- why each opcode may deserve a separate CHIP

## Design Principles

Any follow-on EC opcode should obey the same core rules as the base CHIP:

- fixed-width inputs where practical
- canonical encodings
- deterministic failure on invalid inputs
- no partial stack mutation on failure
- explicit VM cost accounting
- bounded memory and bounded iteration

The addendum assumes secp256k1 unless otherwise noted.

## `OP_MODINV`

### Purpose

`OP_MODINV` computes a modular inverse in the secp256k1 field.

It is useful for:

- affine point arithmetic implemented directly in the VM
- batch inversion tricks used by proof verifiers
- field arithmetic inside custom zero-knowledge verifiers
- generic cryptographic constructions that need division in `F_p`

This is the most broadly useful support primitive beyond `ECADD` and `ECMUL`.

### Proposed interface

#### Inputs

Top-to-bottom stack inputs:

- `value`

#### Outputs

Top-to-bottom stack outputs:

- `inverse`

### Semantics

1. Parse `value` as a canonical 32-byte big-endian field element.
2. Fail if `value` is not canonical or is not in the range `1 <= value < p`.
3. Compute `inverse = value^-1 mod p`.
4. Fail if `value == 0`.
5. Push `inverse` as a canonical 32-byte big-endian field element.

### Why it matters

Pedersen-based constructions and Bulletproof-style verifiers often reduce many inversions to a single inversion plus a linear number of multiplications via batch division. That makes `OP_MODINV` disproportionately useful for verifier code.

Without `OP_MODINV`, a script can still emulate inversion using `OP_DEFINE`/`OP_INVOKE` plus `OP_BEGIN`/`OP_UNTIL`, typically by coding the extended Euclidean algorithm or an exponentiation-based inverse. That is feasible, but it is still a loop-heavy subroutine with on the order of thousands of big-int operations and substantial stack churn, so the VM cost stays materially higher than a native primitive.

### Cost model

`OP_MODINV` should be a fixed-cost primitive, not a loop exposed to script.

Recommended cost properties:

- much cheaper than emulating inversion in script
- cheaper than a full `ECMUL`
- likely in the low-thousands to low-tens-of-thousands of operation cost, depending on the chosen benchmark target
- benchmarked against a reference `libsecp256k1`-style implementation before activation

The final cost should be chosen so that practical verifier code can use the opcode, but unbounded repeated inversion remains expensive enough to discourage abuse.

### Spec questions to resolve

- whether the result is required to be canonical-reduced modulo `p`
- whether the opcode should also expose a batch-inversion form
- whether the cost should be constant or depend on implementation mode

## `OP_ECMULTGEN`

### Purpose

`OP_ECMULTGEN` computes `k * G` for the standard secp256k1 generator `G`.

It is useful for:

- public key generation
- Pedersen commitments with fixed generators
- Schnorr-style verifier constructions
- MuSig-style and threshold signing workflows
- many common proof systems that reuse a fixed base point

This is one of the strongest candidates for a follow-on opcode because it is common, safe, and easier to optimize than generic scalar multiplication.

### Proposed interface

#### Inputs

Top-to-bottom stack inputs:

- `scalar`

#### Outputs

Top-to-bottom stack outputs:

- `result_y`
- `result_x`

### Semantics

1. Parse `scalar` as a canonical 32-byte big-endian integer.
2. Fail if `scalar` is not canonical or is not in the range `1 <= scalar < n`.
3. Compute `R = scalar * G`.
4. Fail if `R` is the point at infinity.
5. Push the resulting coordinates.

### Why it matters

Many verifier formulas and commitment schemes repeatedly multiply the generator by a scalar. A fixed-base multiplication opcode can use precomputed tables and is normally substantially faster than generic `ECMUL`.

Without `OP_ECMULTGEN`, scripts can still implement fixed-base multiplication by calling generic `ECMUL`, or by hardcoding a windowed ladder with `OP_DEFINE`/`OP_INVOKE` and `OP_BEGIN`/`OP_UNTIL`. That is still possible, but it remains bytecode-heavy and loop-heavy, and it keeps paying the generic-multiplication cost even when the base point is fixed.

### Cost model

`OP_ECMULTGEN` should be cheaper than generic `OP_ECMUL`.

Reasonable pricing goals:

- same consensus safety as `ECMUL`
- materially lower execution cost than generic point multiplication
- potentially a few times cheaper than `ECMUL` when the precomputation tables are effective
- bounded enough that fixed-base proofs remain practical without becoming a general compute loophole

### Spec questions to resolve

- whether the opcode should be a dedicated primitive or a parameterized fixed-base form of `ECMUL`
- whether a second fixed base `H` should be standardized for Pedersen commitments

## `OP_ECMULTMULTI`

### Purpose

`OP_ECMULTMULTI` computes a multi-scalar multiplication:

`R = sum(i=1..n) k_i * P_i`

It is useful for:

- Bulletproof verifier equations
- aggregated commitments
- batch signature verification
- MuSig-style multi-party constructions
- any verifier whose dominant cost is a linear combination of curve points

This is the opcode most directly associated with Bulletproof-style workloads.

### Proposed interface

There are two plausible interface styles:

1. a counted flat list of scalar-point tuples
2. a fixed-arity form with a maximum term count

The counted form is more flexible, but the fixed-arity form is easier to cost and bound.

#### Suggested counted form

Top-to-bottom stack inputs:

- `count`
- `k_n`
- `point_n_y`
- `point_n_x`
- ...
- `k_1`
- `point_1_y`
- `point_1_x`

#### Outputs

Top-to-bottom stack outputs:

- `result_y`
- `result_x`

### Semantics

1. Parse `count` as a canonical non-negative integer.
2. Fail if `count` is zero.
3. Fail if `count` exceeds a consensus-defined maximum `MAX_MSM_TERMS`.
4. For each term:
   - parse the scalar canonically and require `1 <= k_i < n`
   - parse the point canonically and require curve membership
5. Compute `R = sum(k_i * P_i)`.
6. Fail if `R` is the point at infinity.
7. Push the resulting coordinates.

### Why it matters

Bulletproof verification is MSM-heavy. The Bulletproofs paper notes that verification of multiple proofs can be batched and that multi-exponentiation is central to practical verification cost. A dedicated MSM opcode makes those workloads realistic in script.

Without `OP_ECMULTMULTI`, a verifier has to expand the MSM into many separate `ECMUL` and `ECADD` steps, usually wrapped in `OP_BEGIN`/`OP_UNTIL` loops and helper functions. That still works, but the VM must pay for every scalar multiply, every addition, and every loop dispatch, which is exactly why MSM-heavy proofs become expensive enough to threaten the current op-cost envelope.

### Cost model

`OP_ECMULTMULTI` should not be free-form.

It needs:

- a strict maximum term count
- a base cost
- a per-term cost
- a memory bound

Recommended cost properties:

- cheaper than doing every term as a separate `ECMUL` + `ECADD`
- still expensive enough that very large MSMs remain bounded by VM limits
- linear or near-linear in the number of terms for consensus clarity
- the per-term cost should be calibrated so a typical Bulletproof verifier stays well under the standard input budget, while very large MSMs remain infeasible

For practical Bulletproof verification, the term cap should be chosen so that a typical verifier fits comfortably inside the existing VM cost envelope for standard inputs.

### Spec questions to resolve

- what `MAX_MSM_TERMS` should be
- whether the term count should be small and fixed, or more flexible with a higher per-term charge
- whether there should be a separate fixed-base MSM form for generator-heavy workloads

## Not Recommended as Part of the Same CHIP

### Pairing checks

Pairing-based opcodes are not a natural next step for this proposal.

They are useful for SNARK- and BLS-style systems, but they raise a different class of complexity and consensus risk than the secp256k1 primitives above.

If the network ever wants pairings, they should likely be proposed in a separate CHIP with their own benchmark and security analysis.

## Benchmark Requirements

Before any follow-on opcode is activated, the CHIP should include:

- a reference implementation benchmark
- a worst-case input benchmark
- cost comparison against emulation in script
- a description of how the opcode fits within the existing operation-cost envelope
- at least one real verifier or protocol sketch that motivates the primitive

## Open Questions

These should be resolved before any of the follow-ons move from addendum to standalone CHIP:

- Should `ECMULTGEN` standardize one generator or two generators?
- Should `ECMULTMULTI` be capped by count, by cost, or by both?
- Should `MODINV` be field-specific or generalized to all VM integers?
- Should any of these opcodes share a common EC opcode family with sub-opcodes instead of individual opcodes?

## Opcode Namespace Proposal

A discussion proposal suggests reserving a single prefix byte for EC arithmetic and using a selector carried as script data rather than as a multi-byte opcode. BCHN's current opcode map already uses `0xbc` for `OP_REVERSEBYTES`, so `0xbc` is not available for this purpose. For this proposal, the first EC bytes should start at `0xd6` so that `0xbd`-`0xbf` remain available for unrelated future proposals:

- `0xd6` = `OP_ECADD`
- `0xd7` = `OP_ECMUL`
- `0xd8` = possible reserved follow-on slot or EC-family prefix
- `0xd9`-`0xde` = possible follow-on EC bytes
- `0xdf`-`0xee` = additional reserve space
- `0xf0`-`0xfe` = additional reserve space

The strongest argument for this approach is opcode-surface conservation. It lets the network standardize a family once, then add narrowly scoped follow-ons without consuming fresh top-level opcode space each time. That matters because the BCHN map does not leave a larger contiguous free range for future EC math.

If the network wants additional room for future curve families beyond the current opcode window, the cleanest contiguous reserve block starts at `0xd6` and runs through `0xfe`:

- `0xd6`-`0xee`
- `0xf0`-`0xfe`

`0xef` is excluded because BCHN uses it as `SPECIAL_TOKEN_PREFIX`, and `0xff` is `INVALIDOPCODE`. That makes `0xd6`-`0xfe` the largest practical reserve region for future EC or post-quantum families, even though `0xef` itself must remain excluded.

The main spec work it requires is:

- defining the selector encoding if a family opcode is used
- defining whether unknown selectors are immediate failures or reserved for future upgrades
- defining how VM cost accounting is attached to the family and selector values
- defining how consensus rules distinguish secp256k1 opcodes from any future curve families

In particular, if the network wants room for a future post-quantum replacement curve, the solution is to reserve a contiguous block starting at `0xd6` and accept that `0xef` is unusable. The network still needs a namespace strategy inside that block, not just more scattered bytes.

## Cost Envelope Summary

Given the current VM Limits model, a standard input with 1,650 unlocking bytes has an operation-cost budget of about `1,352,800` cost units (`800 * (41 + 1650)`), so these opcodes should be judged by whether they enable a full verifier to fit comfortably inside that envelope.

Practical reading:

- `OP_MODINV` should be cheap enough that a verifier can afford a few inversions, but expensive enough that repeated use is not a loophole.
- `OP_ECMULTGEN` should be priced below `ECMUL` enough to matter in verifier-heavy scripts.
- `OP_ECMULTMULTI` should probably be the main workhorse for Bulletproof-style verification, because its value comes from collapsing many curve operations into one bounded primitive.

The forum discussion also emphasized that `ECADD` is orders of magnitude cheaper than emulation, and `ECMUL` is cheaper than `OP_CHECKSIG` in the same general cost regime, which supports keeping the base CHIP focused on the two essential primitives and pushing the rest into narrowly scoped follow-ons.
