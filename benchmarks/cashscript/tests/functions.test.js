import assert from "node:assert/strict";
import test from "node:test";

import { compileFile } from "cashc";
import {
  Contract,
  MockNetworkProvider,
  randomUtxo,
  TransactionBuilder,
  VmTarget,
} from "cashscript";
import {
  buildAddendumArgs,
  buildEcaddArgs,
  buildEcmultgenArgs,
  buildEcmultmultiArgs,
  buildEcmulArgs,
  buildModinvArgs,
  invalidEcFixtures,
} from "../fixtures/ec-fixtures.js";

const artifact = compileFile(
  new URL("../contracts/functions.cash", import.meta.url),
);
const helperNames = artifact.debug?.functions?.map(({ name }) => name) ?? [];

function createContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(artifact, [10n], {
    provider,
    contractType: "p2sh32",
  });
  return { contract, provider };
}

function transactionFor(contract, functionName, args) {
  const utxo = randomUtxo({ satoshis: 100_000n });
  contract.provider.addUtxo(contract.address, utxo);

  return new TransactionBuilder({ provider: contract.provider })
    .addInput(utxo, contract.unlock[functionName](...args))
    .addOutput({ to: contract.address, amount: utxo.satoshis - 3_000n });
}

test("compiles generic user-defined operand helpers to OP_DEFINE and OP_INVOKE", () => {
  assert.deepEqual(
    new Set(helperNames),
    new Set([
      "requirePositive",
      "withinLimit",
      "scaled",
      "score",
      "canonical32",
      "nonzero32",
      "validPointOperands",
      "validEcmulOperands",
      "validEcaddOperands",
      "validModinvOperands",
      "validEcmultgenOperands",
      "validEcmultmultiOperands",
      "validateEcmulOperands",
      "validateEcaddOperands",
      "validateModinvOperands",
      "validateEcmultgenOperands",
      "validateEcmultmultiOperands",
    ]),
  );
  assert.match(artifact.bytecode, /OP_DEFINE/);
  assert.match(artifact.bytecode, /OP_INVOKE/);
});

test("validates ordinary helper-function execution with a MockNetworkProvider UTXO", async () => {
  const { contract } = createContract();
  assert.equal((await contract.getUtxos()).length, 0);

  const validTransaction = transactionFor(contract, "spend", [5n]);
  assert.equal((await contract.getUtxos()).length, 1);
  assert.doesNotThrow(() => validTransaction.debug());

  const nonPositiveTransaction = transactionFor(contract, "spend", [0n]);
  assert.throws(() => nonPositiveTransaction.debug(), /value must be positive/);

  const overLimitTransaction = transactionFor(contract, "spend", [11n]);
  assert.throws(() => overLimitTransaction.debug(), /value exceeds limit/);
});

test("accepts user-supplied generic ECMUL operands", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcmul",
    buildEcmulArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("accepts user-supplied generic ECADD operands", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcadd",
    buildEcaddArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("accepts user-supplied generic MODINV operands", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateModinv",
    buildModinvArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("accepts user-supplied generic ECMULTGEN operands", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcmultgen",
    buildEcmultgenArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("accepts user-supplied generic ECMULTMULTI operands", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcmultmulti",
    buildEcmultmultiArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("accepts the combined addendum operand fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateAddendum",
    buildAddendumArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("rejects a non-canonical ECMUL fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcmul",
    buildEcmulArgs(invalidEcFixtures.nonCanonicalEcmul),
  );

  assert.throws(() => transaction.debug(), /ECMUL operands are invalid/);
});

test("rejects an all-zero EC point fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcmul",
    buildEcmulArgs(invalidEcFixtures.zeroPoint),
  );

  assert.throws(() => transaction.debug(), /ECMUL operands are invalid/);
});

test("rejects a non-canonical MODINV fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateModinv",
    buildModinvArgs(invalidEcFixtures.nonCanonicalModinv),
  );

  assert.throws(() => transaction.debug(), /MODINV operands are invalid/);
});

test("rejects an invalid ECMULTMULTI count fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "simulateEcmultmulti",
    buildEcmultmultiArgs(invalidEcFixtures.invalidEcmultmultiCount),
  );

  assert.throws(() => transaction.debug(), /ECMULTMULTI operands are invalid/);
});
