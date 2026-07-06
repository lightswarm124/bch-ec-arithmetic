# EC Math Fixtures

This folder contains machine-readable fixture sets for the EC math locking-script proposal.

## Layout

- `core/op_ecadd/tests.json` - current CHIP vectors for `OP_ECADD`
- `core/op_ecmul/tests.json` - current CHIP vectors for `OP_ECMUL`
- `proposed/op_modinv/tests.json` - draft vectors for `OP_MODINV`
- `proposed/op_ecmultgen/tests.json` - draft vectors for `OP_ECMULTGEN`
- `proposed/op_ecmultmulti/tests.json` - draft vectors for `OP_ECMULTMULTI`
- `vm/core/op_ecadd/execution.json` - raw bytecode execution vectors for `OP_ECADD`
- `vm/core/op_ecmul/execution.json` - raw bytecode execution vectors for `OP_ECMUL`

## Schema

Each fixture file is a JSON object with:

- `schema`: fixture schema identifier
- `curve`: always `secp256k1`
- `opcode`: opcode name
- `status`: `core` for the current CHIP, `proposed` for addendum opcodes
- `source`: the source document for the opcode definition
- `cases`: array of test cases

Each test case has:

- `id`
- `description`
- `input`
- `expect`

`expect.success` is `true` for success cases and `false` for failure cases.
Failure `error` strings are descriptive only and are not consensus-critical.

## Encoding

- Field elements and scalars are 32-byte big-endian hex strings.
- For fixed-arity opcodes, the `input` object fields are named in the same logical order as the opcode operands.
- For `OP_ECMULTMULTI`, `input.count` is a JSON integer and `input.terms` is an ordered array from first term to last term.
- The JSON files describe logical operands for locking-script validation, not raw serialized transactions. A harness should map each case to the opcode's stack order before execution.

## Coverage

The fixture sets intentionally include edge and failure cases for consensus safety:

- out-of-range scalars and field elements at and above the secp256k1 boundaries
- invalid points such as `(1, 1)` and `(0, 0)`
- operations that would produce the point at infinity
- later-term validation failures in `OP_ECMULTMULTI`
- count/term mismatches in `OP_ECMULTMULTI`

The logical fixtures model operand semantics. The VM execution fixtures in `vm/` cover byte-level locking-script issues such as:

- stack underflow or missing operands
- extra stack items left behind after execution
- non-32-byte pushes and other malformed operand encodings
- minimal-push and canonical-push requirements
- atomic failure with no partial outputs left on the stack

The VM suite currently covers the consensus-critical `OP_ECADD` and `OP_ECMUL` locking-script paths. It can be extended with follow-on opcodes once their interfaces are finalized.

## Validation

Use `npm install` once at the repo root, then `npm run validate` to run both suites in sequence.

Use `npm run validate:fixtures` to load the logical fixture files, validate schema shape, and cross-check all success and failure cases against the published `@bitauth/libauth` package.

Use `npm run validate:vm-fixtures` to execute the VM bytecode fixtures against the published `@bitauth/libauth` BCH VM. If you install the package into a separate npm prefix, pass `--libauth-package-root` to either validator.
