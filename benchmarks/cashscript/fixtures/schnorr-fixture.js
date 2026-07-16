import { hexToBin } from "@bitauth/libauth";

// These deterministic fixtures contain public proof data only. Witnesses and
// nonces are intentionally omitted: this module supplies verifier operands.
export const proofDomainTags = Object.freeze({
  schnorr: "45be058cdf7f726f5fa80e9be10e0db7213f9f1dd678a7b895ee52a1e99d5ed2",
  dleq: "21c0567f6bcfb63262df11213633ca8a181aaf425f102a82e5b2ef91178d7eef",
  pedersen: "10656b2d2e57a7331539fc6ac247989a78490a8fad33c58cb08214cfcfc14dc2",
});

export const proofTokenCategory =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

export const validSchnorrFixtures = Object.freeze({
  primary: Object.freeze({
    statementPointX:
      "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
    statementPointY:
      "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6",
    reconstructedRX:
      "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
    reconstructedRY:
      "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da",
    challenge:
      "11a2f9f4e85abef3416ea3acdd72cfc42e6f66e1324cfca7501e2984646b10f0",
    response:
      "a7d11e37763a453fb8d6cd9facc1f129d281da80b3c7b0f72f3b8ef6da1eec98",
    responseGeneratorX:
      "20da47b8026384af221e7b57599f188de2af3c6e2f7d00a9c1d89e96ced8da7c",
    responseGeneratorY:
      "2511e27e14ec837e1bc87c35dc7f04983c7815826ee896c1a9499a8c2e4eeb77",
    challengePointX:
      "cfc14ad6d7c075b4c22c7ef2d5e94f5fa4a019379303d34b1109e7d282e769ee",
    challengePointY:
      "767888d394939bbfef8ee2de0322ce64dc9715e1f06ac4ba64aec44b6ea9dd9f",
    context: "69f1e54eaa28cd807a9a1c7f142b9a6f0bce842dd89895bfd47d8be4873565e6",
  }),
  alternate: Object.freeze({
    statementPointX:
      "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    statementPointY:
      "ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297",
    reconstructedRX:
      "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
    reconstructedRY:
      "cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37",
    challenge:
      "8714fd1a26155a0abfcf71a8a6c46666c8598d0f398723d5e93bc5a04d20b73d",
    response:
      "d58211631b7fe3bf8123560c1765999238a2253f63f7a9eb87e2d8717214b99f",
    responseGeneratorX:
      "0d29ab1ba3bad12a87a69216b9ef1eca29dc72878fd8b8f0eeb6a6cd2aa3fdaa",
    responseGeneratorY:
      "335218b928c50f3b9b600dfed88a4c12575184651d4041dcde256a4a2dce047e",
    challengePointX:
      "349f920b8ddc125a3be9ca514ebb5c1f2472412be29f52b4f309d2da31c8147f",
    challengePointY:
      "f0258135620b981283ba2b7d9d1afda5d2cc53fa266f909a5c9bb484fed201fc",
    context: "8e24dc936f727cd89adbd0c8f6dc0cd27634ed69bb8b404256a388c7b49b2d4c",
  }),
});

export const validDleqFixture = Object.freeze({
  generatorX:
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  generatorY:
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
  independentPointX:
    "b1dc2faad5c0cff01166eb9ffd30b7c84a7d4ecb6f0080b4f58ba941ffa9a0d5",
  independentPointY:
    "705fe33f06fea6442450932e7f93e9b24a16c4d4d8f2764a14451e4f38b4ac03",
  statementPointX:
    "774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
  statementPointY:
    "d984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b",
  relatedPointX:
    "53dd8fc04a5207636fec40879d283e1d67aadf361c78a2493ea4c93871185f4c",
  relatedPointY:
    "1e3e3fbcdb7bcf593631ba3e3ef05f859ef90e9187fa399185cdfefa83574e9a",
  context: "29178f8def53e238523b9189662bbfefc473d0d0be5bea1188a1be112d410840",
  challenge: "6d36d1a3ff6a5b7deada6add46c5e14c7c85a00a4da855cfe88a065fdfbc24bd",
  response: "4ea4fdf4066e1196e89d687df57f51b04bac7010162f713bc12d92a173f9b233",
  responseGeneratorX:
    "f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
  responseGeneratorY:
    "0ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81",
  challengeStatementX:
    "3cc4c34078f5ae813ed0642482063e34dcfe4f6d2644d5933012d0b024274668",
  challengeStatementY:
    "6e870d81df597ce49ea3dfc6aa32923c5b749420f641257a97c55d2d9246dadb",
  transcript1X:
    "f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
  transcript1Y:
    "0ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81",
  responseIndependentX:
    "4c92436eb2cddac9675c5938aaf51ad8bd12ac63b058ec5e6e97948ebe694461",
  responseIndependentY:
    "67d7e7dd9ebde4bfc193f3d3b3a8a76fb588be38d56c0b74f8b530829ddbbebf",
  challengeRelatedX:
    "02e788ff829f09afca4cda073ea8cb0f7ceecd3bba80043943aa9c897bf92acd",
  challengeRelatedY:
    "24b73f0f521824121da25c95864ee7a0718cac8099b40ecd76dfde86de33295a",
  transcript2X:
    "5271804c0ed1801b2eb319cb76541f4ca801a585392156e4f574d1e2998c9d83",
  transcript2Y:
    "06e14fbfb34e607409320474f7380f29d0e679bbc0dfd0216bc2fad6451be728",
});

export const validPedersenFixture = Object.freeze({
  generatorX:
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  generatorY:
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
  independentPointX:
    "b1dc2faad5c0cff01166eb9ffd30b7c84a7d4ecb6f0080b4f58ba941ffa9a0d5",
  independentPointY:
    "705fe33f06fea6442450932e7f93e9b24a16c4d4d8f2764a14451e4f38b4ac03",
  commitmentX:
    "5d360bf47ee95df90534e144fc795b0212a020f16cbf8509048cf85d1da8fad6",
  commitmentY:
    "d6146acf2f942c92c6bdbf33ce16567b87a2fa0dba62c4071f8b5e7583acd4bf",
  context: "885451348fe6d1406db3ff12c775808a30ce763eb25dfeafa151c04f96bf0d93",
  challenge: "6317794629e3552871aed358ff09b5ee571730525e55194adefc5c5faf520509",
  messageResponse:
    "6b70f25737e758507363f717105aeb23523dd4d68755b3a96ffe737f0d097345",
  blindingResponse:
    "a541ffcae420adff9006506512477f455ebe511879f4214f71d8194c7e9baa7a",
  messageGeneratorX:
    "31c6480f3e2cd9c5e34bc2b7457a41c20d27839574d957fa02c33ede4f770c0d",
  messageGeneratorY:
    "34525a8bcb9ed900e7dbd1dc9d467cee6decab0ff20c1d4cf6cf4c88ff3d7daa",
  blindingIndependentX:
    "34890cdf79facaad24aac68923b3d4ff2f3aad07958b0230efd609ceb6e00a38",
  blindingIndependentY:
    "63a2ce62c0905c7a999719eaaab96bce2cdb18ecf3204c642371f8cc039fcadb",
  challengeCommitmentX:
    "68c2c6b9841b6920f0d495fc58a3661c1578a3109f66ef043540ca0265770e0e",
  challengeCommitmentY:
    "4d40e10aecb28d753a922db5b06e7d6df99a4e6cb612493368fe98b0b451977e",
  reconstructedTX:
    "56bd5b492f6df60a48d76703437cf14ba425ecac37762ef5a13a53aab1d7085b",
  reconstructedTY:
    "fe336fb00783b85b5c7de4f547376179233f4e44c5060a7d9443675e24c12efb",
});

export const invalidProofFixtures = Object.freeze({
  schnorrChallenge: Object.freeze({
    ...validSchnorrFixtures.primary,
    challenge: `${"0".repeat(63)}1`,
  }),
  dleqChallenge: Object.freeze({
    ...validDleqFixture,
    challenge: `${"0".repeat(63)}1`,
  }),
  pedersenChallenge: Object.freeze({
    ...validPedersenFixture,
    challenge: `${"0".repeat(63)}1`,
  }),
  pedersenResponse: Object.freeze({
    ...validPedersenFixture,
    messageResponse: "02",
  }),
});

const bytes = (hex) => hexToBin(hex);

export function buildSchnorrContractArgs(
  fixture = validSchnorrFixtures.primary,
  limit = 10n,
) {
  return [
    limit,
    bytes(fixture.statementPointY),
    bytes(fixture.statementPointX),
    bytes(fixture.context),
  ];
}

export function buildSchnorrProofArgs(fixture = validSchnorrFixtures.primary) {
  return [
    bytes(fixture.challenge),
    bytes(fixture.response),
    bytes(fixture.reconstructedRY),
    bytes(fixture.reconstructedRX),
  ];
}

export function buildProofContractArgs() {
  return [
    bytes(proofDomainTags.schnorr),
    bytes(proofDomainTags.dleq),
    bytes(proofDomainTags.pedersen),
  ];
}

export function buildSchnorrVerifierArgs(
  fixture = validSchnorrFixtures.primary,
) {
  return [
    bytes(fixture.statementPointY),
    bytes(fixture.statementPointX),
    bytes(fixture.context),
    bytes(fixture.challenge),
    bytes(fixture.response),
    bytes(fixture.responseGeneratorY),
    bytes(fixture.responseGeneratorX),
    bytes(fixture.challengePointY),
    bytes(fixture.challengePointX),
    bytes(fixture.reconstructedRY),
    bytes(fixture.reconstructedRX),
  ];
}

export function buildDleqVerifierArgs(fixture = validDleqFixture) {
  return [
    bytes(fixture.generatorY),
    bytes(fixture.generatorX),
    bytes(fixture.independentPointY),
    bytes(fixture.independentPointX),
    bytes(fixture.statementPointY),
    bytes(fixture.statementPointX),
    bytes(fixture.relatedPointY),
    bytes(fixture.relatedPointX),
    bytes(fixture.context),
    bytes(fixture.challenge),
    bytes(fixture.response),
    bytes(fixture.responseGeneratorY),
    bytes(fixture.responseGeneratorX),
    bytes(fixture.challengeStatementY),
    bytes(fixture.challengeStatementX),
    bytes(fixture.transcript1Y),
    bytes(fixture.transcript1X),
    bytes(fixture.responseIndependentY),
    bytes(fixture.responseIndependentX),
    bytes(fixture.challengeRelatedY),
    bytes(fixture.challengeRelatedX),
    bytes(fixture.transcript2Y),
    bytes(fixture.transcript2X),
  ];
}

export function buildDleqVaultContractArgs(
  fixture = validDleqFixture,
  tokenCategory = proofTokenCategory,
) {
  return [
    bytes(proofDomainTags.dleq),
    bytes(fixture.generatorY),
    bytes(fixture.generatorX),
    bytes(fixture.independentPointY),
    bytes(fixture.independentPointX),
    bytes(fixture.statementPointY),
    bytes(fixture.statementPointX),
    bytes(fixture.relatedPointY),
    bytes(fixture.relatedPointX),
    bytes(fixture.context),
    // CashScript token objects use canonical category hex, while
    // OP_UTXOTOKENCATEGORY exposes the VM-byte-order category.
    bytes(tokenCategory).reverse(),
  ];
}

export function buildDleqVaultProofArgs(fixture = validDleqFixture) {
  return [
    bytes(fixture.challenge),
    bytes(fixture.response),
    bytes(fixture.responseGeneratorY),
    bytes(fixture.responseGeneratorX),
    bytes(fixture.challengeStatementY),
    bytes(fixture.challengeStatementX),
    bytes(fixture.transcript1Y),
    bytes(fixture.transcript1X),
    bytes(fixture.responseIndependentY),
    bytes(fixture.responseIndependentX),
    bytes(fixture.challengeRelatedY),
    bytes(fixture.challengeRelatedX),
    bytes(fixture.transcript2Y),
    bytes(fixture.transcript2X),
  ];
}

export function buildPedersenVerifierArgs(fixture = validPedersenFixture) {
  return [
    bytes(fixture.generatorY),
    bytes(fixture.generatorX),
    bytes(fixture.independentPointY),
    bytes(fixture.independentPointX),
    bytes(fixture.commitmentY),
    bytes(fixture.commitmentX),
    bytes(fixture.context),
    bytes(fixture.challenge),
    bytes(fixture.messageResponse),
    bytes(fixture.blindingResponse),
    bytes(fixture.messageGeneratorY),
    bytes(fixture.messageGeneratorX),
    bytes(fixture.blindingIndependentY),
    bytes(fixture.blindingIndependentX),
    bytes(fixture.challengeCommitmentY),
    bytes(fixture.challengeCommitmentX),
    bytes(fixture.reconstructedTY),
    bytes(fixture.reconstructedTX),
  ];
}

export function buildPedersenStateContractArgs(
  fixture = validPedersenFixture,
  maximumValue = 1_000n,
) {
  return [
    bytes(proofDomainTags.pedersen),
    bytes(fixture.generatorY),
    bytes(fixture.generatorX),
    bytes(fixture.independentPointY),
    bytes(fixture.independentPointX),
    bytes(fixture.commitmentY),
    bytes(fixture.commitmentX),
    bytes(fixture.context),
    maximumValue,
  ];
}

export function buildPedersenOpeningArgs(
  fixture = validPedersenFixture,
  claimedValue = 42n,
) {
  return [
    claimedValue,
    bytes(fixture.challenge),
    bytes(fixture.messageResponse),
    bytes(fixture.blindingResponse),
    bytes(fixture.messageGeneratorY),
    bytes(fixture.messageGeneratorX),
    bytes(fixture.blindingIndependentY),
    bytes(fixture.blindingIndependentX),
    bytes(fixture.challengeCommitmentY),
    bytes(fixture.challengeCommitmentX),
    bytes(fixture.reconstructedTY),
    bytes(fixture.reconstructedTX),
  ];
}
