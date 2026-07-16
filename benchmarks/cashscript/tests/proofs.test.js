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
  buildDleqVerifierArgs,
  buildPedersenVerifierArgs,
  buildProofContractArgs,
  buildSchnorrVerifierArgs,
  invalidProofFixtures,
  validDleqFixture,
  validSchnorrFixtures,
} from "../fixtures/schnorr-fixture.js";

const artifact = compileFile(
  new URL("../contracts/proofs.cash", import.meta.url),
);
const helperNames = artifact.debug?.functions?.map(({ name }) => name) ?? [];

function createContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(artifact, buildProofContractArgs(), {
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
    .addOutput({ to: contract.address, amount: utxo.satoshis - 10_000n });
}

test("compiles the minimal Schnorr, DLEQ, and Pedersen helpers", () => {
  assert.deepEqual(
    new Set(helperNames),
    new Set([
      "canonical32",
      "nonzero32",
      "validScalar",
      "validPoint",
      "verifySchnorrOperands",
      "verifyDleqOperands",
      "verifyPedersenOperands",
    ]),
  );
  assert.deepEqual(
    new Set(artifact.abi.map(({ name }) => name)),
    new Set(["verifySchnorr", "verifyDleq", "verifyPedersen"]),
  );
  assert.match(artifact.bytecode, /OP_DEFINE/);
  assert.match(artifact.bytecode, /OP_INVOKE/);
});

test("verifies a compact Schnorr operand fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifySchnorr",
    buildSchnorrVerifierArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("verifies a second Schnorr statement supplied by fixture data", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifySchnorr",
    buildSchnorrVerifierArgs(validSchnorrFixtures.alternate),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("rejects a Schnorr fixture with a tampered challenge", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifySchnorr",
    buildSchnorrVerifierArgs(invalidProofFixtures.schnorrChallenge),
  );

  assert.throws(() => transaction.debug(), /invalid Schnorr challenge/);
});

test("verifies a Chaum-Pedersen DLEQ operand fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifyDleq",
    buildDleqVerifierArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("keeps DLEQ intermediate operand roles distinct", () => {
  assert.notEqual(
    validDleqFixture.challengeStatementX,
    validDleqFixture.transcript2X,
  );
  assert.notEqual(
    validDleqFixture.responseIndependentX,
    validDleqFixture.transcript2X,
  );
  assert.notEqual(
    validDleqFixture.challengeRelatedX,
    validDleqFixture.transcript2X,
  );
});

test("rejects a DLEQ fixture with a tampered challenge", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifyDleq",
    buildDleqVerifierArgs(invalidProofFixtures.dleqChallenge),
  );

  assert.throws(() => transaction.debug(), /invalid DLEQ challenge/);
});

test("verifies a Pedersen commitment opening operand fixture", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifyPedersen",
    buildPedersenVerifierArgs(),
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("rejects a Pedersen fixture with a non-canonical response", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    "verifyPedersen",
    buildPedersenVerifierArgs(invalidProofFixtures.pedersenResponse),
  );

  assert.throws(() => transaction.debug(), /Pedersen operands are invalid/);
});
