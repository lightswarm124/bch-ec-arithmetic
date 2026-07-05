# EC Math VM Fixtures

This folder contains raw-bytecode execution fixtures for the EC math proposal.

## Layout

- `core/op_ecadd/execution.json` - raw bytecode execution vectors for `OP_ECADD`
- `core/op_ecmul/execution.json` - raw bytecode execution vectors for `OP_ECMUL`

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
- `unlockingBytecode`
- `lockingBytecode`
- `expect`

`unlockingBytecode` and `lockingBytecode` are raw script bytecode hex strings.

`expect.success` is `true` for success cases and `false` for failure cases.
`expect.stack` lists the final stack top-to-bottom as hex strings, so failure
cases can assert that the opcode left the pre-failure stack unchanged.
Failure `error` strings are descriptive only and are not consensus-critical.

## Coverage

The VM fixtures focus on consensus exploit boundaries that require actual
script execution:

- empty-stack and underflow failures
- malformed push encodings in unlocking bytecode
- non-32-byte stack items at the opcode boundary
- invalid secp256k1 points
- infinity-producing additions
- stack preservation on failure

## Validation

Use `npm install` once at the repo root, then `npm run validate:vm-fixtures` to execute every VM fixture file against the published `@bitauth/libauth` BCH VM.
