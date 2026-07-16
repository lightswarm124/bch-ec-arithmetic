import "dotenv/config";

import {
  deriveHdPath,
  deriveHdPrivateNodeFromSeed,
  deriveSeedFromBip39Mnemonic,
  encodeCashAddress,
  hash160,
  secp256k1,
} from "@bitauth/libauth";
import { compileFile } from "cashc";
import {
  Contract,
  ElectrumNetworkProvider,
  Network,
  MockNetworkProvider,
  randomUtxo,
  SignatureTemplate,
  TransactionBuilder,
  VmTarget,
} from "cashscript";
import {
  boundedEmulatedDleqFixture,
  boundedPedersenFixture,
  buildBoundedEmulatedDleqProofArgs,
  buildBoundedPedersenContractArgs,
  buildBoundedPedersenOpeningArgs,
  buildEmulatedDleqContractArgs,
} from "../fixtures/emulation-fixture.js";

const DERIVATION_PATH = "m/44'/1'/0'/0/0";
const CONTRACT_FUNDING_SATOSHIS = 20_000n;
const FEE_RATE_SATS_PER_BYTE = 1;
const MAXIMUM_FEE_SATOSHIS = 10_000n;
const CHIPNET_EMULATION = process.env.CHIPNET_EMULATION ?? "both";

function deriveWallet() {
  if (!process.env.MNEMONIC) throw new Error("MNEMONIC is not set");

  const seed = deriveSeedFromBip39Mnemonic(process.env.MNEMONIC);
  const root = deriveHdPrivateNodeFromSeed(seed, {
    assumeValidity: true,
    throwErrors: true,
  });
  const node = deriveHdPath(root, DERIVATION_PATH);
  if (typeof node === "string") throw new Error(node);

  const publicKey = secp256k1.derivePublicKeyCompressed(node.privateKey);
  const address = encodeCashAddress({
    prefix: "bchtest",
    type: "p2pkh",
    payload: hash160(publicKey),
    throwErrors: true,
  }).address;

  return { address, privateKey: node.privateKey };
}

async function waitForUtxo(provider, address, predicate) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const utxo = (await provider.getUtxos(address)).find(predicate);
    if (utxo) return utxo;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`Timed out waiting for a UTXO at ${address}`);
}

function chooseBchUtxo(utxos, minimum) {
  return utxos
    .filter((utxo) => !utxo.token && utxo.satoshis >= minimum)
    .sort((a, b) => (a.satoshis < b.satoshis ? -1 : 1))[0];
}

function summarizeUsage(usage) {
  return {
    arithmeticCost: String(usage.arithmeticCost),
    densityControlLength: String(usage.densityControlLength),
    evaluatedInstructionCount: String(usage.evaluatedInstructionCount),
    maximumOperationCost: String(usage.maximumOperationCost),
    operationCost: String(usage.operationCost),
    stackPushedBytes: String(usage.stackPushedBytes),
  };
}

function verifyConfigurationWithMocknet(configuration) {
  const artifact = compileFile(
    new URL(`../contracts/${configuration.source}`, import.meta.url),
  );
  const provider = new MockNetworkProvider({
    vmTarget: VmTarget.BCH_2026_05,
  });
  const contract = new Contract(artifact, configuration.contractArgs, {
    provider,
    contractType: "p2sh32",
  });
  const utxo = randomUtxo({ satoshis: CONTRACT_FUNDING_SATOSHIS });
  provider.addUtxo(contract.address, utxo);
  const transaction = new TransactionBuilder({ provider })
    .addInput(
      utxo,
      contract.unlock[configuration.entrypoint](...configuration.unlockArgs),
    )
    .addOutput({ to: contract.address, amount: 1_000n });

  transaction.debug();
  const [usage] = transaction.getVmResourceUsage();
  console.log(`Mocknet verification passed for ${configuration.name}`, {
    vm: summarizeUsage(usage),
  });
}

async function runCase(provider, wallet, configuration) {
  verifyConfigurationWithMocknet(configuration);
  const artifact = compileFile(
    new URL(`../contracts/${configuration.source}`, import.meta.url),
  );
  const contract = new Contract(artifact, configuration.contractArgs, {
    provider,
    contractType: "p2sh32",
  });

  let contractUtxo = (await contract.getUtxos()).find(
    (utxo) => !utxo.token && utxo.satoshis >= CONTRACT_FUNDING_SATOSHIS,
  );
  let fundingTxid = null;

  if (!contractUtxo) {
    const sourceUtxo = chooseBchUtxo(
      await provider.getUtxos(wallet.address),
      CONTRACT_FUNDING_SATOSHIS + 1_000n,
    );
    if (!sourceUtxo) {
      throw new Error(
        `No BCH-only CHIPNET UTXO can fund ${configuration.name}`,
      );
    }

    const fundingTransaction = new TransactionBuilder({
      provider,
      maximumFeeSatoshis: MAXIMUM_FEE_SATOSHIS,
    })
      .addInput(
        sourceUtxo,
        new SignatureTemplate(wallet.privateKey).unlockP2PKH(),
      )
      .addOutput({
        to: contract.address,
        amount: CONTRACT_FUNDING_SATOSHIS,
      })
      .addBchChangeOutputIfNeeded({
        to: wallet.address,
        feeRate: FEE_RATE_SATS_PER_BYTE,
      });

    fundingTransaction.debug();
    const fundingFee = fundingTransaction.calculateTransactionFee();
    console.log(`Broadcasting CHIPNET ${configuration.name} funding`, {
      from: wallet.address,
      to: contract.address,
      sourceUtxo: `${sourceUtxo.txid}:${sourceUtxo.vout}`,
      amount: CONTRACT_FUNDING_SATOSHIS.toString(),
      feeSatoshis: fundingFee.feeSats.toString(),
    });

    const fundingDetails = await fundingTransaction.send();
    fundingTxid = fundingDetails.txid;
    contractUtxo = await waitForUtxo(
      provider,
      contract.address,
      (utxo) => utxo.txid === fundingTxid && !utxo.token,
    );
  }

  const spendTransaction = new TransactionBuilder({
    provider,
    maximumFeeSatoshis: MAXIMUM_FEE_SATOSHIS,
  })
    .addInput(
      contractUtxo,
      contract.unlock[configuration.entrypoint](...configuration.unlockArgs),
    )
    .addOutput({ to: wallet.address, amount: 1_000n })
    .addBchChangeOutputIfNeeded({
      to: wallet.address,
      feeRate: FEE_RATE_SATS_PER_BYTE,
    });

  spendTransaction.debug();
  const [usage] = spendTransaction.getVmResourceUsage();
  const spendFee = spendTransaction.calculateTransactionFee();
  console.log(`Broadcasting CHIPNET ${configuration.name} spend`, {
    from: `${contractUtxo.txid}:${contractUtxo.vout}`,
    to: wallet.address,
    fundingTxid,
    feeSatoshis: spendFee.feeSats.toString(),
    vm: summarizeUsage(usage),
  });

  const spendDetails = await spendTransaction.send();
  console.log(`CHIPNET ${configuration.name} test complete`, {
    walletAddress: wallet.address,
    contractAddress: contract.address,
    fundingTxid,
    spendTxid: spendDetails.txid,
    remainingContractUtxos: (await contract.getUtxos()).length,
  });
}

async function main() {
  if (process.env.CHIPNET_BROADCAST !== "1") {
    throw new Error(
      "Refusing to broadcast. Re-run with CHIPNET_BROADCAST=1 when a real CHIPNET spend is intended.",
    );
  }

  const configurations = {
    "bounded-dleq": {
      name: "bounded DLEQ emulation",
      source: "ec-emulation-bounded.cash",
      contractArgs: buildEmulatedDleqContractArgs(boundedEmulatedDleqFixture),
      entrypoint: "verifyBounded",
      unlockArgs: buildBoundedEmulatedDleqProofArgs(),
    },
    pedersen: {
      name: "bounded Pedersen opening emulation",
      source: "ec-pedersen-bounded.cash",
      contractArgs: buildBoundedPedersenContractArgs(boundedPedersenFixture),
      entrypoint: "openBounded",
      unlockArgs: buildBoundedPedersenOpeningArgs(),
    },
  };

  const selected =
    CHIPNET_EMULATION === "both"
      ? ["bounded-dleq", "pedersen"]
      : [CHIPNET_EMULATION];
  if (selected.some((name) => !configurations[name])) {
    throw new Error(
      `Unsupported CHIPNET_EMULATION=${CHIPNET_EMULATION}; expected both, bounded-dleq, or pedersen`,
    );
  }

  const wallet = deriveWallet();
  const provider = new ElectrumNetworkProvider(Network.CHIPNET);
  console.log("Using CHIPNET wallet", {
    address: wallet.address,
    derivationPath: DERIVATION_PATH,
    cases: selected,
  });

  for (const name of selected) {
    await runCase(provider, wallet, configurations[name]);
  }
}

await main();
