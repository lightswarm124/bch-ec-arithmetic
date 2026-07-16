import assert from "node:assert/strict";
import test from "node:test";

import { hexToBin } from "@bitauth/libauth";
import { compileFile } from "cashc";
import {
  Contract,
  MockNetworkProvider,
  randomUtxo,
  TransactionBuilder,
  VmTarget,
} from "cashscript";
import {
  buildLinkedDleqContractArgs,
  buildLinkedDleqStageArgs,
} from "../fixtures/emulation-fixture.js";
import {
  buildLinkedPedersenRangeProofArgs,
  buildPedersenRangeProofContractArgs,
  invalidPedersenRangeProofFixtures,
} from "../fixtures/range-proof-fixture.js";
import {
  buildBulletproofContractArgs,
  buildLinkedBulletproofProofArgs,
  bulletproofRangeProofFixture,
} from "../fixtures/bulletproof-fixture.js";

const artifacts = {
  dleq: compileFile(
    new URL(
      "../contracts/linked/ec-emulation-linked-dleq.cash",
      import.meta.url,
    ),
  ),
  pedersen: compileFile(
    new URL(
      "../contracts/linked/ec-pedersen-range-proof-linked.cash",
      import.meta.url,
    ),
  ),
  bulletproof: compileFile(
    new URL(
      "../contracts/linked/ec-bulletproof-range-proof-linked.cash",
      import.meta.url,
    ),
  ),
};

function createContract(kind) {
  const provider = new MockNetworkProvider({
    vmTarget: VmTarget.BCH_2026_05,
  });
  const artifact = artifacts[kind];
  const constructorArgs = {
    dleq: buildLinkedDleqContractArgs(),
    pedersen: buildPedersenRangeProofContractArgs(),
    bulletproof: buildBulletproofContractArgs(),
  }[kind];
  const contract = new Contract(artifact, constructorArgs, {
    provider,
    contractType: "p2sh32",
  });
  return { contract, provider };
}

function buildTransaction(contract, args, inputCount, functionNames = []) {
  const utxos = Array.from({ length: inputCount }, () =>
    randomUtxo({ satoshis: 100_000n }),
  );
  for (const utxo of utxos) contract.provider.addUtxo(contract.address, utxo);

  const transaction = new TransactionBuilder({ provider: contract.provider });
  for (const [index, utxo] of utxos.entries()) {
    const inputArgs = Array.isArray(args[0]) ? args[index] : args;
    const functionName = functionNames[index] ?? "verifyLinked";
    transaction.addInput(utxo, contract.unlock[functionName](...inputArgs));
  }
  transaction.addOutput({
    to: contract.address,
    amount: BigInt(inputCount * 100_000 - 50_000),
  });
  return transaction;
}

function tamperedState(args) {
  return [
    ...args.slice(0, -1),
    hexToBin(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
  ];
}

test("linked DLEQ records a one-operation density overrun", () => {
  const { contract } = createContract("dleq");
  const args = buildLinkedDleqStageArgs();
  const transaction = buildTransaction(contract, args, 2, [
    "verifyFirst",
    "verifySecond",
  ]);
  assert.throws(() => transaction.debug(), /density limit/);
});

test("linked DLEQ rejects a tampered state commitment", () => {
  const { contract } = createContract("dleq");
  const args = buildLinkedDleqStageArgs();
  const transaction = buildTransaction(contract, args, 2, [
    "verifyFirst",
    "verifySecond",
  ]);
  transaction.inputs[1].unlocker = contract.unlock.verifySecond(
    ...tamperedState(args[1]),
  );
  assert.throws(
    () => transaction.debug(),
    /Require statement failed|non-truthy|density limit/,
  );
});

test("linked Pedersen records its current linked-stack limitation", () => {
  const { contract } = createContract("pedersen");
  const transaction = buildTransaction(
    contract,
    buildLinkedPedersenRangeProofArgs(),
    4,
  );
  assert.throws(
    () => transaction.debug(),
    /non-truthy|Cannot destructure|density limit/,
  );
});

test("linked Pedersen rejects a changed branch response", () => {
  const { contract } = createContract("pedersen");
  const args = buildLinkedPedersenRangeProofArgs(
    invalidPedersenRangeProofFixtures.response,
  );
  const transaction = buildTransaction(contract, args, 4);
  assert.throws(
    () => transaction.debug(),
    /Require statement failed|non-truthy|density limit/,
  );
});

test("linked Bulletproof records its density overrun", () => {
  const { contract } = createContract("bulletproof");
  const transaction = buildTransaction(
    contract,
    buildLinkedBulletproofProofArgs(bulletproofRangeProofFixture),
    3,
  );
  assert.throws(() => transaction.debug(), /density limit/);
});

test("linked Bulletproof rejects a tampered state commitment", () => {
  const { contract } = createContract("bulletproof");
  const args = buildLinkedBulletproofProofArgs();
  const transaction = buildTransaction(contract, args, 3);
  transaction.inputs[2].unlocker = contract.unlock.verifyLinked(
    ...tamperedState(args),
  );
  assert.throws(
    () => transaction.debug(),
    /Require statement failed|density limit/,
  );
});
