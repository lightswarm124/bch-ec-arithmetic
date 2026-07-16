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
  boundedPedersenFixture,
  boundedEmulatedDleqFixture,
  buildBoundedPedersenContractArgs,
  buildBoundedPedersenOpeningArgs,
  buildEmulatedDleqContractArgs,
  buildBoundedEmulatedDleqProofArgs,
  buildEmulatedDleqProofArgs,
  buildBatchedEmulatedDleqProofArgs,
  emulatedSecp256k1,
  invalidBoundedPedersenFixtures,
  invalidBoundedEmulatedDleqFixtures,
  invalidEmulatedDleqFixtures,
  validEmulatedDleqFixture,
  verifyBoundedPedersenOpening,
} from "../fixtures/emulation-fixture.js";
import {
  buildPedersenRangeProofArgs,
  buildPedersenRangeProofContractArgs,
  invalidPedersenRangeProofFixtures,
  pedersenRangeProofFixture,
  verifyPedersenRangeProof,
} from "../fixtures/range-proof-fixture.js";
import {
  buildBulletproofContractArgs,
  buildBulletproofProofArgs,
  bulletproofRangeProofFixture,
  invalidBulletproofRangeProofFixtures,
  verifyBulletproofRangeProof,
} from "../fixtures/bulletproof-fixture.js";

const fullArtifact = compileFile(
  new URL("../contracts/ec-emulation.cash", import.meta.url),
);
const boundedArtifact = compileFile(
  new URL("../contracts/ec-emulation-bounded.cash", import.meta.url),
);
const pedersenArtifact = compileFile(
  new URL("../contracts/ec-pedersen-bounded.cash", import.meta.url),
);
const rangeProofArtifact = compileFile(
  new URL("../contracts/ec-pedersen-range-proof.cash", import.meta.url),
);
const bulletproofArtifact = compileFile(
  new URL("../contracts/ec-bulletproof-range-proof.cash", import.meta.url),
);
const batchedDleqArtifact = compileFile(
  new URL("../contracts/ec-emulation-batched.cash", import.meta.url),
);

function createContract(
  artifact = fullArtifact,
  fixture = validEmulatedDleqFixture,
) {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(
    artifact,
    buildEmulatedDleqContractArgs(fixture),
    { provider, contractType: "p2sh32" },
  );
  return { contract, provider };
}

function createPedersenContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(
    pedersenArtifact,
    buildBoundedPedersenContractArgs(boundedPedersenFixture),
    { provider, contractType: "p2sh32" },
  );
  return { contract, provider };
}

function createRangeProofContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(
    rangeProofArtifact,
    buildPedersenRangeProofContractArgs(pedersenRangeProofFixture),
    { provider, contractType: "p2sh32" },
  );
  return { contract, provider };
}

function createBulletproofContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(
    bulletproofArtifact,
    buildBulletproofContractArgs(bulletproofRangeProofFixture),
    { provider, contractType: "p2sh32" },
  );
  return { contract, provider };
}

function createBatchedDleqContract() {
  const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
  const contract = new Contract(
    batchedDleqArtifact,
    buildEmulatedDleqContractArgs(validEmulatedDleqFixture),
    { provider, contractType: "p2sh32" },
  );
  return { contract, provider };
}

function transactionFor(contract, args, entrypoint = "verify") {
  const utxo = randomUtxo({ satoshis: 100_000n });
  contract.provider.addUtxo(contract.address, utxo);

  return new TransactionBuilder({ provider: contract.provider })
    .addInput(utxo, contract.unlock[entrypoint](...args))
    .addOutput({ to: contract.address, amount: utxo.satoshis - 10_000n });
}

test("compiles the full and bounded secp256k1 emulation helpers", () => {
  assert.match(fullArtifact.bytecode, /OP_DEFINE/);
  assert.match(fullArtifact.bytecode, /OP_INVOKE/);
  assert.match(boundedArtifact.bytecode, /OP_DEFINE/);
  assert.match(boundedArtifact.bytecode, /OP_INVOKE/);
  assert.match(pedersenArtifact.bytecode, /OP_DEFINE/);
  assert.match(pedersenArtifact.bytecode, /OP_INVOKE/);
  assert.ok(fullArtifact.bytecode.length > 2_000);
  assert.deepEqual(
    fullArtifact.abi.map(({ name }) => name),
    ["verify"],
  );
  assert.deepEqual(
    boundedArtifact.abi.map(({ name }) => name),
    ["verifyBounded"],
  );
  assert.deepEqual(
    pedersenArtifact.abi.map(({ name }) => name),
    ["openBounded"],
  );
  assert.deepEqual(
    rangeProofArtifact.abi.map(({ name }) => name),
    ["verifyRangeProof"],
  );
  assert.deepEqual(
    bulletproofArtifact.abi.map(({ name }) => name),
    ["verifyBulletproof"],
  );
  assert.deepEqual(
    batchedDleqArtifact.abi.map(({ name }) => name),
    ["verifyBatched"],
  );
});

test("the off-chain reference verifies the complete 256-bit DLEQ equation", () => {
  const fixture = validEmulatedDleqFixture;
  const first = emulatedSecp256k1.add(
    emulatedSecp256k1.multiply(fixture.generator, fixture.response),
    emulatedSecp256k1.negate(
      emulatedSecp256k1.multiply(fixture.statementPoint, fixture.challenge),
    ),
  );
  const second = emulatedSecp256k1.add(
    emulatedSecp256k1.multiply(fixture.independentPoint, fixture.response),
    emulatedSecp256k1.negate(
      emulatedSecp256k1.multiply(fixture.relatedPoint, fixture.challenge),
    ),
  );

  assert.deepEqual(first, fixture.transcript1);
  assert.deepEqual(second, fixture.transcript2);
});

test("the full 256-bit CashScript emulation reaches the density limit", () => {
  const { contract } = createContract();
  const transaction = transactionFor(contract, buildEmulatedDleqProofArgs());

  assert.throws(() => transaction.debug(), /density limit/);
});

test("bounded CashScript emulation verifies the same equation", () => {
  const { contract } = createContract(
    boundedArtifact,
    boundedEmulatedDleqFixture,
  );
  const transaction = transactionFor(
    contract,
    buildBoundedEmulatedDleqProofArgs(),
    "verifyBounded",
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("bounded CashScript emulation rejects a tampered response", () => {
  const { contract } = createContract(
    boundedArtifact,
    boundedEmulatedDleqFixture,
  );
  const transaction = transactionFor(
    contract,
    buildBoundedEmulatedDleqProofArgs(
      invalidBoundedEmulatedDleqFixtures.response,
    ),
    "verifyBounded",
  );

  assert.throws(
    () => transaction.debug(),
    /Require statement failed|non-truthy value on top of the stack/,
  );
});

test("rejects a DLEQ proof with a challenge not bound to its scalar", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildEmulatedDleqProofArgs(invalidEmulatedDleqFixtures.challenge),
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("rejects a DLEQ proof with a tampered transcript point", () => {
  const { contract } = createContract();
  const transaction = transactionFor(
    contract,
    buildEmulatedDleqProofArgs(invalidEmulatedDleqFixtures.transcript),
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("rejects the point-at-infinity sentinel as a DLEQ public point", () => {
  const { contract } = createContract(
    fullArtifact,
    invalidEmulatedDleqFixtures.infinity,
  );
  const transaction = transactionFor(contract, buildEmulatedDleqProofArgs());

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("reports the emulated verifier resource usage", () => {
  const { contract } = createContract(
    boundedArtifact,
    boundedEmulatedDleqFixture,
  );
  const transaction = transactionFor(
    contract,
    buildBoundedEmulatedDleqProofArgs(),
    "verifyBounded",
  );
  const [usage] = transaction.getVmResourceUsage();

  assert.ok(usage.evaluatedInstructionCount > 0);
  assert.ok(usage.operationCost > 0);
  assert.ok(usage.hashDigestIterations > 0);
});

test("records that full-width VM execution exceeds its operation budget", () => {
  const { contract } = createContract();
  const transaction = transactionFor(contract, buildEmulatedDleqProofArgs());

  assert.throws(
    () => transaction.getVmResourceUsage(),
    (error) => {
      assert.match(error.message, /density limit/);
      const match = error.message.match(
        /Maximum operation cost: (\d+).*?operation cost following operation: (\d+)/s,
      );
      assert.ok(match);
      assert.ok(Number(match[2]) > Number(match[1]));
      return true;
    },
  );
});

test("bounded emulation checks a public Pedersen opening and range bound", () => {
  assert.equal(verifyBoundedPedersenOpening(), true);
  const { contract } = createPedersenContract();
  const transaction = transactionFor(
    contract,
    buildBoundedPedersenOpeningArgs(),
    "openBounded",
  );

  assert.doesNotThrow(() => transaction.debug());
});

test("bounded Pedersen emulation rejects a changed opening", () => {
  assert.equal(
    verifyBoundedPedersenOpening(invalidBoundedPedersenFixtures.value),
    false,
  );
  const { contract } = createPedersenContract();
  const transaction = transactionFor(
    contract,
    buildBoundedPedersenOpeningArgs(invalidBoundedPedersenFixtures.value),
    "openBounded",
  );

  assert.throws(
    () => transaction.debug(),
    /Require statement failed|non-truthy value on top of the stack/,
  );
});

test("verifies a complete zero-knowledge Pedersen range proof off-chain", () => {
  assert.equal(verifyPedersenRangeProof(), true);
  assert.equal(
    verifyPedersenRangeProof(invalidPedersenRangeProofFixtures.challenge),
    false,
  );
  assert.equal(
    verifyPedersenRangeProof(invalidPedersenRangeProofFixtures.response),
    false,
  );
  assert.equal(
    verifyPedersenRangeProof(invalidPedersenRangeProofFixtures.transcript),
    false,
  );
});

test("complete Pedersen range-proof equations remain over the VM density limit", () => {
  const { contract } = createRangeProofContract();
  const transaction = transactionFor(
    contract,
    buildPedersenRangeProofArgs(),
    "verifyRangeProof",
  );

  assert.throws(() => transaction.debug(), /density limit/);
});

test("complete Pedersen range proof rejects a tampered challenge before EC work", () => {
  const { contract } = createRangeProofContract();
  const transaction = transactionFor(
    contract,
    buildPedersenRangeProofArgs(invalidPedersenRangeProofFixtures.challenge),
    "verifyRangeProof",
  );

  assert.throws(() => transaction.debug(), /Require statement failed/);
});

test("verifies a complete two-bit Bulletproof range proof off-chain", () => {
  assert.equal(bulletproofRangeProofFixture.rangeBits, 2);
  assert.equal(verifyBulletproofRangeProof(), true);
});

test("Bulletproof range proof rejects tampered statement, scalar, and IPA data", () => {
  assert.equal(
    verifyBulletproofRangeProof(
      invalidBulletproofRangeProofFixtures.commitment,
    ),
    false,
  );
  assert.equal(
    verifyBulletproofRangeProof(invalidBulletproofRangeProofFixtures.scalar),
    false,
  );
  assert.equal(
    verifyBulletproofRangeProof(invalidBulletproofRangeProofFixtures.ipa),
    false,
  );
});

test("CashScript Bulletproof verifier reaches the VM density limit", () => {
  const { contract } = createBulletproofContract();
  const transaction = transactionFor(
    contract,
    buildBulletproofProofArgs(bulletproofRangeProofFixture),
    "verifyBulletproof",
  );

  assert.throws(
    () => transaction.getVmResourceUsage(),
    (error) => {
      assert.match(error.message, /density limit/);
      const match = error.message.match(
        /Maximum operation cost: (\d+).*?operation cost following operation: (\d+)/s,
      );
      assert.ok(match);
      assert.equal(Number(match[1]), 3_012_000);
      assert.equal(Number(match[2]), 3_012_017);
      return true;
    },
  );
});

test("transcript-bound batched DLEQ remains over the VM density limit", () => {
  const { contract } = createBatchedDleqContract();
  const transaction = transactionFor(
    contract,
    buildBatchedEmulatedDleqProofArgs(validEmulatedDleqFixture),
    "verifyBatched",
  );

  assert.throws(
    () => transaction.getVmResourceUsage(),
    (error) => {
      assert.match(error.message, /density limit/);
      const match = error.message.match(
        /Maximum operation cost: (\d+).*?operation cost following operation: (\d+)/s,
      );
      assert.ok(match);
      assert.equal(Number(match[1]), 2_126_400);
      assert.equal(Number(match[2]), 2_126_574);
      return true;
    },
  );
});
