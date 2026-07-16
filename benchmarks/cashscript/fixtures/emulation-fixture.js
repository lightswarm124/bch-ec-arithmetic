import { hexToBin, binToHex } from "@bitauth/libauth";
import { sha256 } from "@cashscript/utils";

const P = BigInt(
  "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
);
const N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);

const G = Object.freeze({
  x: BigInt(
    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  ),
  y: BigInt(
    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
  ),
});

const mod = (value, modulus) => {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
};

const modPow = (base, exponent, modulus) => {
  let result = 1n;
  let remaining = exponent;
  let value = mod(base, modulus);

  while (remaining > 0n) {
    if (remaining % 2n === 1n) result = mod(result * value, modulus);
    remaining /= 2n;
    if (remaining > 0n) value = mod(value * value, modulus);
  }

  return result;
};

// Deterministically derive an independent secp256k1 generator. The
// try-and-increment hash-to-curve construction keeps its discrete-log
// relationship to G unknown to the fixture author.
export const hashToCurvePoint = (seedHex) => {
  const digest = sha256(hexToBin(seedHex));
  let x = mod(BigInt(`0x${binToHex(digest)}`), P);

  while (true) {
    const rhs = mod(x * x * x + 7n, P);
    const y = modPow(rhs, (P + 1n) / 4n, P);
    if (y !== 0n && mod(y * y, P) === rhs) return { x, y };
    x = mod(x + 1n, P);
  }
};

const inverse = (value, modulus) => {
  let a = mod(value, modulus);
  let b = modulus;
  let coefficientA = 1n;
  let coefficientB = 0n;

  while (a !== 0n) {
    const quotient = b / a;
    [b, a] = [a, b % a];
    [coefficientB, coefficientA] = [
      coefficientA,
      coefficientB - quotient * coefficientA,
    ];
  }

  return mod(coefficientB, modulus);
};

const add = (first, second) => {
  if (first.infinity) return second;
  if (second.infinity) return first;

  if (first.x === second.x) {
    if (first.y !== second.y || first.y === 0n) {
      return { infinity: true };
    }
    const slope = mod(3n * first.x * first.x * inverse(2n * first.y, P), P);
    const x = mod(slope * slope - first.x - second.x, P);
    const y = mod(slope * (first.x - x) - first.y, P);
    return { x, y };
  }

  const slope = mod((second.y - first.y) * inverse(second.x - first.x, P), P);
  const x = mod(slope * slope - first.x - second.x, P);
  const y = mod(slope * (first.x - x) - first.y, P);
  return { x, y };
};

const multiply = (point, scalar) => {
  let remaining = mod(scalar, N);
  let result = { infinity: true };
  let addend = point;

  while (remaining > 0n) {
    if (remaining % 2n === 1n) result = add(result, addend);
    remaining /= 2n;
    if (remaining > 0n) addend = add(addend, addend);
  }

  return result;
};

const negate = (point) =>
  point.infinity ? point : { x: point.x, y: mod(P - point.y, P) };

const pointBytes = (point) => {
  const pad = (value) => value.toString(16).padStart(64, "0");
  return [pad(point.x), pad(point.y)];
};

const bytes = (hex) => hexToBin(hex);
const toHex = (value) => value.toString(16).padStart(64, "0");

const proofDomainTag =
  "21c0567f6bcfb63262df11213633ca8a181aaf425f102a82e5b2ef91178d7eef";
const context =
  "2a4d6f64656c2d656d756c617465642d72616e67652d70726f6f662d76310000";

const witness = 23n;
const nonce = 41n;
const independentPoint = hashToCurvePoint(
  "8b4f4d2a4e0e5d4e4a75f0a4c3f5b9e6b4b2d2f9a6b8c4e7d1f0a2b3c4d5e6f7",
);
const statementPoint = multiply(G, witness);
const relatedPoint = multiply(independentPoint, witness);
const transcript1 = multiply(G, nonce);
const transcript2 = multiply(independentPoint, nonce);

const transcript = [
  proofDomainTag,
  proofDomainTag,
  toHex(G.x),
  toHex(G.y),
  toHex(independentPoint.x),
  toHex(independentPoint.y),
  toHex(statementPoint.x),
  toHex(statementPoint.y),
  toHex(relatedPoint.x),
  toHex(relatedPoint.y),
  toHex(transcript1.x),
  toHex(transcript1.y),
  toHex(transcript2.x),
  toHex(transcript2.y),
  context,
].join("");

const challengeBytes = sha256(bytes(transcript));
const challenge = BigInt(`0x${binToHex(challengeBytes)}`);
const response = mod(nonce + challenge * witness, N);
const responseGenerator = multiply(G, response);
const challengeStatement = multiply(statementPoint, challenge);
const responseIndependent = multiply(independentPoint, response);
const challengeRelated = multiply(relatedPoint, challenge);

const batchTranscript = [
  proofDomainTag,
  proofDomainTag,
  "01",
  binToHex(challengeBytes),
  toHex(response),
  toHex(transcript1.x),
  toHex(transcript1.y),
  toHex(transcript2.x),
  toHex(transcript2.y),
  context,
].join("");
const batchChallengeBytes = sha256(bytes(batchTranscript));
const batchChallenge = BigInt(`0x${binToHex(batchChallengeBytes)}`);

export const validEmulatedDleqFixture = Object.freeze({
  proofDomainTag,
  context,
  generator: Object.freeze({ x: G.x, y: G.y }),
  independentPoint: Object.freeze({
    x: independentPoint.x,
    y: independentPoint.y,
  }),
  statementPoint: Object.freeze({ x: statementPoint.x, y: statementPoint.y }),
  relatedPoint: Object.freeze({ x: relatedPoint.x, y: relatedPoint.y }),
  challengeBytes: binToHex(challengeBytes),
  challenge,
  batchChallengeBytes: binToHex(batchChallengeBytes),
  batchChallenge,
  response,
  transcript1: Object.freeze({ x: transcript1.x, y: transcript1.y }),
  transcript2: Object.freeze({ x: transcript2.x, y: transcript2.y }),
  responseGenerator: Object.freeze({
    x: responseGenerator.x,
    y: responseGenerator.y,
  }),
  challengeStatement: Object.freeze({
    x: challengeStatement.x,
    y: challengeStatement.y,
  }),
  responseIndependent: Object.freeze({
    x: responseIndependent.x,
    y: responseIndependent.y,
  }),
  challengeRelated: Object.freeze({
    x: challengeRelated.x,
    y: challengeRelated.y,
  }),
});

export const linkedDleqFixture = validEmulatedDleqFixture;

export const invalidEmulatedDleqFixtures = Object.freeze({
  infinity: Object.freeze({
    ...validEmulatedDleqFixture,
    generator: Object.freeze({ x: 0n, y: 0n }),
  }),
  response: Object.freeze({
    ...validEmulatedDleqFixture,
    response: validEmulatedDleqFixture.response + 1n,
  }),
  challenge: Object.freeze({
    ...validEmulatedDleqFixture,
    challengeBytes: `${"0".repeat(63)}1`,
  }),
  transcript: Object.freeze({
    ...validEmulatedDleqFixture,
    transcript1: Object.freeze({
      x: validEmulatedDleqFixture.transcript1.x + 1n,
      y: validEmulatedDleqFixture.transcript1.y,
    }),
  }),
  batchChallenge: Object.freeze({
    ...validEmulatedDleqFixture,
    batchChallenge: validEmulatedDleqFixture.batchChallenge + 1n,
  }),
});

export function buildEmulatedDleqContractArgs(
  fixture = validEmulatedDleqFixture,
) {
  return [
    bytes(fixture.proofDomainTag),
    fixture.generator.x,
    fixture.generator.y,
    fixture.independentPoint.x,
    fixture.independentPoint.y,
    fixture.statementPoint.x,
    fixture.statementPoint.y,
    fixture.relatedPoint.x,
    fixture.relatedPoint.y,
    bytes(fixture.context),
  ];
}

export function buildLinkedDleqContractArgs(fixture = linkedDleqFixture) {
  return buildEmulatedDleqContractArgs(fixture);
}

export function buildEmulatedDleqProofArgs(fixture = validEmulatedDleqFixture) {
  return [
    bytes(fixture.challengeBytes),
    fixture.challenge,
    fixture.response,
    fixture.transcript1.x,
    fixture.transcript1.y,
    fixture.transcript2.x,
    fixture.transcript2.y,
  ];
}

function linkedDleqStageStateFor(fixture) {
  return sha256(
    bytes(
      [
        toHex(fixture.challenge),
        toHex(fixture.response),
        toHex(fixture.transcript1.x),
        toHex(fixture.transcript1.y),
      ].join(""),
    ),
  );
}

export function buildLinkedDleqStageArgs(fixture = linkedDleqFixture) {
  const stageState = new Uint8Array([...linkedDleqStageStateFor(fixture), 0]);
  return [
    [
      fixture.challenge,
      fixture.response,
      fixture.transcript1.x,
      fixture.transcript1.y,
      stageState,
    ],
    [
      fixture.challenge,
      fixture.response,
      fixture.transcript1.x,
      fixture.transcript1.y,
      fixture.transcript2.x,
      fixture.transcript2.y,
      bytes(fixture.challengeBytes),
      stageState,
    ],
  ];
}

export function buildLinkedDleqProofArgs(fixture = linkedDleqFixture) {
  return buildLinkedDleqStageArgs(fixture);
}

export function buildBatchedEmulatedDleqProofArgs(
  fixture = validEmulatedDleqFixture,
) {
  return [
    bytes(fixture.challengeBytes),
    fixture.challenge,
    fixture.response,
    fixture.transcript1.x,
    fixture.transcript1.y,
    fixture.transcript2.x,
    fixture.transcript2.y,
    fixture.batchChallenge,
  ];
}

export const boundedEmulatedDleqFixture = Object.freeze({
  ...validEmulatedDleqFixture,
  statementPoint: validEmulatedDleqFixture.generator,
  relatedPoint: validEmulatedDleqFixture.independentPoint,
  transcript1: validEmulatedDleqFixture.generator,
  transcript2: validEmulatedDleqFixture.independentPoint,
  challengeByte: "01",
  challenge: 1n,
  response: 2n,
});

export const invalidBoundedEmulatedDleqFixtures = Object.freeze({
  response: Object.freeze({
    ...boundedEmulatedDleqFixture,
    response: 3n,
  }),
});

export function buildBoundedEmulatedDleqProofArgs(
  fixture = boundedEmulatedDleqFixture,
) {
  return [
    bytes(fixture.challengeByte),
    fixture.challenge,
    fixture.response,
    fixture.transcript1.x,
    fixture.transcript1.y,
    fixture.transcript2.x,
    fixture.transcript2.y,
  ];
}

const boundedPedersenValue = 2n;
const boundedPedersenBlinding = 1n;
const boundedPedersenCommitment = add(
  multiply(G, boundedPedersenValue),
  independentPoint,
);

export const boundedPedersenFixture = Object.freeze({
  generator: Object.freeze({ x: G.x, y: G.y }),
  independentPoint: Object.freeze({
    x: independentPoint.x,
    y: independentPoint.y,
  }),
  commitment: Object.freeze({
    x: boundedPedersenCommitment.x,
    y: boundedPedersenCommitment.y,
  }),
  value: boundedPedersenValue,
  blinding: boundedPedersenBlinding,
  maximumValue: 3n,
});

export const invalidBoundedPedersenFixtures = Object.freeze({
  value: Object.freeze({
    ...boundedPedersenFixture,
    value: 3n,
  }),
  blinding: Object.freeze({
    ...boundedPedersenFixture,
    blinding: 2n,
  }),
});

export function buildBoundedPedersenContractArgs(
  fixture = boundedPedersenFixture,
) {
  return [
    fixture.generator.x,
    fixture.generator.y,
    fixture.independentPoint.x,
    fixture.independentPoint.y,
    fixture.commitment.x,
    fixture.commitment.y,
    fixture.maximumValue,
  ];
}

export function buildBoundedPedersenOpeningArgs(
  fixture = boundedPedersenFixture,
) {
  return [fixture.value, fixture.blinding];
}

export function verifyBoundedPedersenOpening(fixture = boundedPedersenFixture) {
  if (
    fixture.value < 0n ||
    fixture.value > fixture.maximumValue ||
    fixture.value >= 4n ||
    fixture.blinding < 0n ||
    fixture.blinding >= 4n
  ) {
    return false;
  }

  const commitment = add(
    multiply(fixture.generator, fixture.value),
    multiply(fixture.independentPoint, fixture.blinding),
  );
  return (
    commitment.x === fixture.commitment.x &&
    commitment.y === fixture.commitment.y
  );
}

export const emulatedSecp256k1 = Object.freeze({
  P,
  N,
  add,
  multiply,
  negate,
  generator: Object.freeze({ x: G.x, y: G.y }),
  hashToCurvePoint,
});
