import { binToHex, hexToBin } from "@bitauth/libauth";
import { sha256 } from "@cashscript/utils";
import {
  emulatedSecp256k1,
  validEmulatedDleqFixture,
} from "./emulation-fixture.js";

const N = emulatedSecp256k1.N;
const { add, multiply, negate } = emulatedSecp256k1;

const rangeProofTagHash =
  "7bb2c8d5c7a756fe0d8f875f6fba5c35bb5c9a4d1685fdd8f5b1fc9d6a6d6f31";
const rangeProofContext =
  "72616e67652d70726f6f662d6f722d7631000000000000000000000000000000";
const rangeProofMaximum = 3n;
const rangeProofValue = 2n;
const rangeProofBlinding = 7n;
const rangeProofNonce = 11n;
const fakeChallenges = [13n, 17n, 0n, 19n];
const fakeResponses = [23n, 29n, 0n, 31n];

const mod = (value, modulus = N) => {
  const result = value % modulus;
  return result < 0n ? result + modulus : result;
};

const toHex = (value) => value.toString(16).padStart(64, "0");
const pointBytes = (point) => toHex(point.x) + toHex(point.y);
const pointEqual = (first, second) =>
  first.infinity === second.infinity &&
  (first.infinity || (first.x === second.x && first.y === second.y));

function rangePoints(fixture) {
  const generator = fixture.generator;
  const differences = [
    generator,
    multiply(generator, 2n),
    multiply(generator, 3n),
  ];

  return [
    fixture.commitment,
    ...differences.map((point) => add(fixture.commitment, negate(point))),
  ];
}

function hashRangeTranscript(fixture, branches) {
  const transcript = [
    fixture.tagHash,
    fixture.tagHash,
    pointBytes(fixture.generator),
    pointBytes(fixture.independentPoint),
    pointBytes(fixture.commitment),
    ...branches.map(({ transcript }) => pointBytes(transcript)),
    fixture.context,
  ].join("");
  return sha256(hexToBin(transcript));
}

const rangeProofBase = {
  tagHash: rangeProofTagHash,
  context: rangeProofContext,
  generator: validEmulatedDleqFixture.generator,
  independentPoint: validEmulatedDleqFixture.independentPoint,
  value: rangeProofValue,
  blinding: rangeProofBlinding,
  maximumValue: rangeProofMaximum,
};

const commitment = add(
  multiply(rangeProofBase.generator, rangeProofValue),
  multiply(rangeProofBase.independentPoint, rangeProofBlinding),
);

const fixtureWithCommitment = { ...rangeProofBase, commitment };
const differences = rangePoints(fixtureWithCommitment);
const branches = fakeChallenges.map((challenge, index) => {
  if (index === Number(rangeProofValue)) {
    return {
      challenge: 0n,
      response: 0n,
      transcript: multiply(
        fixtureWithCommitment.independentPoint,
        rangeProofNonce,
      ),
    };
  }

  return {
    challenge,
    response: fakeResponses[index],
    transcript: add(
      multiply(fixtureWithCommitment.independentPoint, fakeResponses[index]),
      negate(multiply(differences[index], challenge)),
    ),
  };
});

const challengeBytes = hashRangeTranscript(fixtureWithCommitment, branches);
const challenge = BigInt(`0x${binToHex(challengeBytes)}`);
const actualChallenge = mod(
  challenge -
    branches.reduce(
      (total, branch, index) =>
        index === Number(rangeProofValue) ? total : total + branch.challenge,
      0n,
    ),
);
const actualResponse = mod(
  rangeProofNonce + actualChallenge * rangeProofBlinding,
);
branches[Number(rangeProofValue)] = {
  challenge: actualChallenge,
  response: actualResponse,
  transcript: branches[Number(rangeProofValue)].transcript,
};

export const pedersenRangeProofFixture = Object.freeze({
  ...fixtureWithCommitment,
  challengeBytes: binToHex(challengeBytes),
  challenge,
  branches: Object.freeze(branches.map((branch) => Object.freeze(branch))),
});

export const invalidPedersenRangeProofFixtures = Object.freeze({
  challenge: Object.freeze({
    ...pedersenRangeProofFixture,
    challengeBytes: `${pedersenRangeProofFixture.challengeBytes.slice(0, -2)}00`,
  }),
  response: Object.freeze({
    ...pedersenRangeProofFixture,
    branches: Object.freeze(
      pedersenRangeProofFixture.branches.map((branch, index) =>
        index === 2
          ? Object.freeze({ ...branch, response: branch.response + 1n })
          : branch,
      ),
    ),
  }),
  transcript: Object.freeze({
    ...pedersenRangeProofFixture,
    branches: Object.freeze(
      pedersenRangeProofFixture.branches.map((branch, index) =>
        index === 2
          ? Object.freeze({
              ...branch,
              transcript: Object.freeze({
                x: branch.transcript.x + 1n,
                y: branch.transcript.y,
              }),
            })
          : branch,
      ),
    ),
  }),
});

export function buildPedersenRangeProofContractArgs(
  fixture = pedersenRangeProofFixture,
) {
  return [
    hexToBin(fixture.tagHash),
    fixture.generator.x,
    fixture.generator.y,
    fixture.independentPoint.x,
    fixture.independentPoint.y,
    fixture.commitment.x,
    fixture.commitment.y,
    hexToBin(fixture.context),
    fixture.maximumValue,
  ];
}

export function buildPedersenRangeProofArgs(
  fixture = pedersenRangeProofFixture,
) {
  return [
    hexToBin(fixture.challengeBytes),
    fixture.challenge,
    ...fixture.branches.flatMap((branch) => [
      branch.challenge,
      branch.response,
      branch.transcript.x,
      branch.transcript.y,
    ]),
  ];
}

export function buildLinkedPedersenRangeProofArgs(
  fixture = pedersenRangeProofFixture,
) {
  const args = buildPedersenRangeProofArgs(fixture);
  const state = [
    fixture.tagHash,
    fixture.context,
    fixture.challengeBytes,
    toHex(fixture.challenge),
    ...fixture.branches.flatMap((branch) => [
      toHex(branch.challenge),
      toHex(branch.response),
      toHex(branch.transcript.x),
      toHex(branch.transcript.y),
    ]),
  ].join("");
  return [...args, sha256(hexToBin(state))];
}

export function verifyPedersenRangeProof(fixture = pedersenRangeProofFixture) {
  if (
    fixture.value < 0n ||
    fixture.value > fixture.maximumValue ||
    fixture.maximumValue !== rangeProofMaximum
  ) {
    return false;
  }

  const expectedChallengeBytes = hashRangeTranscript(fixture, fixture.branches);
  const expectedChallenge = BigInt(`0x${binToHex(expectedChallengeBytes)}`);
  if (
    binToHex(expectedChallengeBytes) !== fixture.challengeBytes ||
    expectedChallenge !== fixture.challenge ||
    expectedChallenge >= N
  ) {
    return false;
  }

  const challengeSum = fixture.branches.reduce(
    (total, branch) => total + branch.challenge,
    0n,
  );
  if (mod(challengeSum) !== fixture.challenge) return false;

  const differences = rangePoints(fixture);
  return fixture.branches.every((branch, index) => {
    if (
      branch.challenge < 0n ||
      branch.challenge >= N ||
      branch.response < 0n ||
      branch.response >= N
    ) {
      return false;
    }

    const reconstructed = add(
      multiply(fixture.independentPoint, branch.response),
      negate(multiply(differences[index], branch.challenge)),
    );
    return pointEqual(reconstructed, branch.transcript);
  });
}
