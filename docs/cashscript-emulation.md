# CashScript emulation findings

## Scope

These experiments answer a focused question: what happens when secp256k1 EC
arithmetic is expressed with user-defined CashScript functions and ordinary
integer operations instead of native EC opcodes?

The answer is directly relevant to the proposal's motivation. The emulated
contracts accept user-supplied values and implement the proof equations, but
the full-width paths exceed the current BCH per-input resource limit. These
are emulation measurements; they are not measurements of the proposed native
opcode costs.

## Measured results

The measurements use `VmTarget.BCH_2026_05` and P2SH32 contracts:

| Verifier | Operation cost | Density maximum | Result |
| --- | ---: | ---: | --- |
| Full DLEQ | 1,788,813 | 1,788,800 | 13 over |
| Pedersen range proof `[0, 3]` | 2,294,424 | 2,294,400 | 24 over |
| Bulletproof range proof `[0, 3]` | 3,012,017 | 3,012,000 | 17 over |
| Batched DLEQ | 2,126,574 | 2,126,400 | 174 over |

An overage of one operation is still a VM failure. The density allowance is
not rounded up.

The linked-input prototypes show the architectural direction used by larger
verifiers: staged DLEQ reached one operation over its measured limit, while
the linked Bulletproof remained 1,294 operations over and the linked Pedersen
prototype still had an EC stack/control-flow failure. These are useful
measurements, not successful production deployments.

## What passed

The bounded DLEQ and bounded Pedersen contracts passed Mocknet validation and
were broadcast on CHIPNET after the local gate:

| Case | Spend transaction |
| --- | --- |
| Bounded DLEQ emulation | `54572fd9e4bb40deccdbf518841ace2b11ed63f0e73ab83776e91db1b7045bcc` |
| Bounded Pedersen opening | `6bf6b6167fc0bf5996cd28573205c3045d0625267f1fcba6a3151ad3b1ac365d` |

The bounded contracts are execution demonstrations. Their scalar loops and
challenge handling are intentionally restricted, so they are not substitutes
for full-width production proof verifiers. The complete Pedersen OR proof is
a zero-knowledge range-proof shape; the bounded Pedersen contract verifies a
revealed opening instead.

## Interpretation for native opcodes

User-defined functions compile to `OP_DEFINE`/`OP_INVOKE` and make complex
helpers possible. They improve organization and reuse, but they do not remove
the repeated field multiplication, reduction, inversion, point addition, and
scalar-multiplication work. That is why native EC/scalar operations are the
meaningful next A/B comparison.

Native `OP_ECADD` and `OP_ECMUL` would replace the corresponding curve
operation inside these proof equations; they would not remove transcript
hashing, scalar checks, proof parsing, covenant logic, or every field
operation around the curve call.

The benchmark does not invent a native operation-cost estimate because the
installed CashScript/VM environment does not expose the proposed operations.
Native results should be measured once an implementation is available.

## Security boundary

The full-width reference paths perform the intended mathematical checks and
reject tampered fixtures in the off-chain reference tests. The bounded paths
are intentionally limited. The linked prototypes are not production-secure
verifiers, and no full-width proof was broadcast.

See [the proposal comparison](./ec-opcode-proposal-comparison.md) for the
operation-by-operation mapping and the Groth16 distinction.
