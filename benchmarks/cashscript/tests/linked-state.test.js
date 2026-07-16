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
  buildLinkedStateContractArgs,
  buildLinkedStateStepArgs,
  invalidLinkedStateFixtures,
  linkedStateFixture,
} from "../fixtures/linked-state-fixture.js";

const artifact = compileFile(
  new URL("../contracts/linked-state.cash", import.meta.url),
);

function createContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(artifact, buildLinkedStateContractArgs(), {
    provider,
    contractType: "p2sh32",
  });
  return { contract, provider };
}

function transactionFor(contract, firstArgs, secondArgs, inputCount = 2) {
  const utxos = Array.from({ length: inputCount }, () =>
    randomUtxo({ satoshis: 100_000n }),
  );
  for (const utxo of utxos) contract.provider.addUtxo(contract.address, utxo);

  const transaction = new TransactionBuilder({ provider: contract.provider });
  if (utxos[0]) {
    transaction.addInput(utxos[0], contract.unlock.step(...firstArgs));
  }
  if (utxos[1]) {
    transaction.addInput(utxos[1], contract.unlock.step(...secondArgs));
  }
  transaction.addOutput({
    to: contract.address,
    amount: BigInt(inputCount * 100_000 - 10_000),
  });
  return transaction;
}

test("compiles the linked-input state handoff harness", () => {
  assert.match(artifact.bytecode, /OP_INPUTBYTECODE/);
  assert.match(artifact.bytecode, /OP_DEFINE/);
  assert.match(artifact.bytecode, /OP_INVOKE/);
  assert.deepEqual(
    artifact.abi.map(({ name }) => name),
    ["step"],
  );
});

test("links a user-supplied intermediate state across two inputs", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildLinkedStateStepArgs(
      linkedStateFixture.initialState,
      linkedStateFixture.middleState,
    ),
    buildLinkedStateStepArgs(
      linkedStateFixture.middleState,
      linkedStateFixture.finalState,
    ),
  );

  assert.doesNotThrow(() => transaction.debug());
  const builtTransaction = transaction.buildLibauthTransaction(true);
  assert.ok(transaction.getTransactionSize() <= 100_000n);
  for (const input of builtTransaction.inputs) {
    assert.ok(input.unlockingBytecode.length <= 10_000);
  }
  for (const usage of transaction.getVmResourceUsage()) {
    assert.ok(usage.operationCost < usage.maximumOperationCost);
  }
});

test("rejects a transaction with stages in the wrong input positions", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildLinkedStateStepArgs(
      linkedStateFixture.middleState,
      linkedStateFixture.finalState,
    ),
    buildLinkedStateStepArgs(
      linkedStateFixture.initialState,
      linkedStateFixture.middleState,
    ),
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("rejects a state handoff with a mismatched intermediate value", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildLinkedStateStepArgs(
      linkedStateFixture.initialState,
      linkedStateFixture.middleState,
    ),
    buildLinkedStateStepArgs(
      invalidLinkedStateFixtures.middleState,
      linkedStateFixture.finalState,
    ),
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("rejects a tampered terminal state", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildLinkedStateStepArgs(
      linkedStateFixture.initialState,
      linkedStateFixture.middleState,
    ),
    buildLinkedStateStepArgs(
      linkedStateFixture.middleState,
      invalidLinkedStateFixtures.finalState,
    ),
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("rejects a transaction with a missing linked stage", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildLinkedStateStepArgs(
      linkedStateFixture.initialState,
      linkedStateFixture.middleState,
    ),
    [],
    1,
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});
