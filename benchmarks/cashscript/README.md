# CashScript EC arithmetic benchmark

This benchmark is the executable evidence package for the EC arithmetic
proposal. It is intentionally separate from the consensus fixture sets in
the repository root.

## Layout

- `contracts/` — CashScript contracts for operand handling, EC emulation,
  DLEQ, Pedersen, Bulletproof, and linked-input experiments
- `fixtures/` — public valid/invalid proof data and off-chain reference logic
- `tests/` — Mocknet correctness checks and BCH VM resource measurements
- `integration/` — explicit CHIPNET runner for bounded demonstrations

The contracts use CashScript `next` user-defined functions. The compiler is
not modified here. Every `.cash` entrypoint and imported source is pinned with
`pragma cashscript 0.14.0;`. The installed compiler package is
`cashc@0.14.0-next.1`; this compiler compares pragmas against the numeric
release version and does not accept prerelease text in the pragma directive.
See the [CashScript pragma documentation](https://cashscript.org/docs/language/contracts#pragma).

## Local checks

From the repository root:

```sh
npm run test:cashscript
npm run test:cashscript:linked
```

The first command covers the reusable-function demo, minimal proof operands,
full emulated proof comparisons, and the generic linked-state handoff. The
second command runs the exploratory staged DLEQ/Pedersen/Bulletproof variants;
their expected density-limit and stack limitations are recorded findings,
not passing production verifiers.

The complete repository validation is:

```sh
npm test
```

## CHIPNET checks

The CHIPNET runner first verifies the same transaction against Mocknet UTXOs.
It refuses to broadcast unless `CHIPNET_BROADCAST=1` is set:

```sh
CHIPNET_BROADCAST=1 CHIPNET_EMULATION=bounded-dleq \
  npm run test:cashscript:chipnet

CHIPNET_BROADCAST=1 CHIPNET_EMULATION=pedersen \
  npm run test:cashscript:chipnet
```

Only the bounded DLEQ and bounded Pedersen demonstrations have been
broadcast. The complete proof paths remain VM-limit comparison artifacts.

Keep the CHIPNET mnemonic in a local `.env` file only; the repository ignores
environment files by default. To reproduce the broadcast with your own
wallet, copy the placeholder and edit it locally:

```sh
cp .env.example .env
$EDITOR .env
```

Set `MNEMONIC` in `.env` to your own CHIPNET BIP39 seed phrase. The runner
derives `m/44'/1'/0'/0/0`, selects a BCH-only UTXO from that address, performs
the Mocknet gate, and only then broadcasts when `CHIPNET_BROADCAST=1` is set.
Alternatively, provide the variable for one shell invocation without writing
it to disk:

```sh
MNEMONIC='your own mnemonic here' CHIPNET_BROADCAST=1 \
  CHIPNET_EMULATION=bounded-dleq npm run test:cashscript:chipnet
```

Never paste a real mnemonic into documentation, shell history, issue reports,
or committed files.

See [the findings](../../docs/cashscript-emulation.md) and [the proposal
comparison](../../docs/ec-opcode-proposal-comparison.md) for the conclusions.
