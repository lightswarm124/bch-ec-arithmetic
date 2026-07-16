import { binToHex, hexToBin } from "@bitauth/libauth";
import { sha256 } from "@cashscript/utils";
import { emulatedSecp256k1 } from "./emulation-fixture.js";

const { N, add, hashToCurvePoint, multiply, negate } = emulatedSecp256k1;

const mod = (value) => {
  const result = value % N;
  return result < 0n ? result + N : result;
};

const scalarInverse = (value) => {
  let result = 1n;
  let base = mod(value);
  let exponent = N - 2n;

  while (exponent > 0n) {
    if (exponent % 2n === 1n) result = mod(result * base);
    base = mod(base * base);
    exponent /= 2n;
  }

  return result;
};

const toHex = (value) => mod(value).toString(16).padStart(64, "0");

const pointHex = (point) => {
  if (point.infinity) return "00".repeat(64);
  return `${point.x.toString(16).padStart(64, "0")}${point.y
    .toString(16)
    .padStart(64, "0")}`;
};

const pointEqual = (first, second) => {
  if (first.infinity || second.infinity)
    return first.infinity === second.infinity;
  return first.x === second.x && first.y === second.y;
};

const validPoint = (point) => {
  if (
    !point ||
    point.infinity ||
    typeof point.x !== "bigint" ||
    typeof point.y !== "bigint"
  ) {
    return false;
  }

  const { P } = emulatedSecp256k1;
  return (
    point.x >= 0n &&
    point.x < P &&
    point.y >= 0n &&
    point.y < P &&
    modField(point.y * point.y) === modField(point.x * point.x * point.x + 7n)
  );
};

const modField = (value) => {
  const { P } = emulatedSecp256k1;
  const result = value % P;
  return result < 0n ? result + P : result;
};

const sumPoints = (points) =>
  points.reduce((sum, point) => add(sum, point), { infinity: true });

const multiscalar = (scalars, points) =>
  scalars.reduce(
    (sum, scalar, index) => add(sum, multiply(points[index], scalar)),
    { infinity: true },
  );

const innerProduct = (left, right) =>
  left.reduce((sum, value, index) => mod(sum + value * right[index]), 0n);

const deriveScalar = (...parts) => {
  const digest = sha256(hexToBin(parts.join("")));
  const scalar = mod(BigInt(`0x${binToHex(digest)}`));
  return scalar === 0n ? 1n : scalar;
};

const deriveGenerator = (label) => hashToCurvePoint(label);

const DOMAIN =
  "62756c6c657470726f6f662d736563703235366b2d72616e67652d763100000000";
const CONTEXT =
  "4250436f6d70617269736f6e2d72616e67652d322d6269742d7631000000000000";

const generators = Object.freeze({
  G: Object.freeze([
    deriveGenerator(
      "62756c6c657470726f6f662d672d302d763100000000000000000000000000",
    ),
    deriveGenerator(
      "62756c6c657470726f6f662d672d312d763100000000000000000000000000",
    ),
  ]),
  H: Object.freeze([
    deriveGenerator(
      "62756c6c657470726f6f662d682d302d763100000000000000000000000000",
    ),
    deriveGenerator(
      "62756c6c657470726f6f662d682d312d763100000000000000000000000000",
    ),
  ]),
  value: deriveGenerator(
    "62756c6c657470726f6f662d706564657273656e2d762d763100000000000000",
  ),
  blinding: deriveGenerator(
    "62756c6c657470726f6f662d706564657273656e2d682d763100000000000000",
  ),
  innerProduct: deriveGenerator(
    "62756c6c657470726f6f662d696e6e65722d70726f647563742d752d763100",
  ),
});

const value = 2n;
const blinding = 17n;
const alpha = 19n;
const rho = 23n;
const sL = [29n, 31n];
const sR = [37n, 41n];
const tau1 = 43n;
const tau2 = 47n;
const bits = [value & 1n, (value >> 1n) & 1n];
const aR = bits.map((bit) => bit - 1n);

const commitment = add(
  multiply(generators.value, value),
  multiply(generators.blinding, blinding),
);
const A = add(
  add(multiscalar(bits, generators.G), multiscalar(aR, generators.H)),
  multiply(generators.blinding, alpha),
);
const S = add(
  add(multiscalar(sL, generators.G), multiscalar(sR, generators.H)),
  multiply(generators.blinding, rho),
);

const challengeY = deriveScalar(
  DOMAIN,
  CONTEXT,
  pointHex(commitment),
  pointHex(A),
  pointHex(S),
);
const challengeZ = deriveScalar(
  DOMAIN,
  CONTEXT,
  "01",
  toHex(challengeY),
  pointHex(commitment),
  pointHex(A),
  pointHex(S),
);

const powers = (scalar, length) => {
  const result = [];
  let current = 1n;
  for (let index = 0; index < length; index += 1) {
    result.push(current);
    current = mod(current * scalar);
  }
  return result;
};

const yPowers = powers(challengeY, 2);
const twoPowers = [1n, 2n];
const l0 = bits.map((bit) => mod(bit - challengeZ));
const l1 = sL.map(mod);
const r0 = aR.map((valueAtIndex, index) =>
  mod(
    yPowers[index] * (valueAtIndex + challengeZ) +
      challengeZ * challengeZ * twoPowers[index],
  ),
);
const r1 = sR.map((valueAtIndex, index) => mod(yPowers[index] * valueAtIndex));
const t0 = innerProduct(l0, r0);
const t1 = mod(innerProduct(l0, r1) + innerProduct(l1, r0));
const t2 = innerProduct(l1, r1);

const T1 = add(
  multiply(generators.value, t1),
  multiply(generators.blinding, tau1),
);
const T2 = add(
  multiply(generators.value, t2),
  multiply(generators.blinding, tau2),
);
const challengeX = deriveScalar(
  DOMAIN,
  CONTEXT,
  "02",
  toHex(challengeY),
  toHex(challengeZ),
  pointHex(commitment),
  pointHex(A),
  pointHex(S),
  pointHex(T1),
  pointHex(T2),
);

const challengeX2 = mod(challengeX * challengeX);
const l = l0.map((valueAtIndex, index) =>
  mod(valueAtIndex + l1[index] * challengeX),
);
const r = r0.map((valueAtIndex, index) =>
  mod(valueAtIndex + r1[index] * challengeX),
);
const tHat = innerProduct(l, r);
const tauX = mod(
  tau2 * challengeX2 + tau1 * challengeX + challengeZ * challengeZ * blinding,
);
const mu = mod(alpha + rho * challengeX);

const hPrime = generators.H.map((point, index) =>
  multiply(point, scalarInverse(yPowers[index])),
);
const delta = mod(
  (challengeZ - challengeZ * challengeZ) * innerProduct([1n, 1n], yPowers) -
    challengeZ * challengeZ * challengeZ * innerProduct([1n, 1n], twoPowers),
);
const pCommitment = add(
  add(
    add(A, multiply(S, challengeX)),
    negate(multiply(sumPoints(generators.G), challengeZ)),
  ),
  multiscalar(
    yPowers.map((yPower, index) =>
      mod(challengeZ * yPower + challengeZ * challengeZ * twoPowers[index]),
    ),
    hPrime,
  ),
);
const unblindedPCommitment = add(
  pCommitment,
  negate(multiply(generators.blinding, mu)),
);

const L = add(
  add(multiply(generators.G[1], l[0]), multiply(hPrime[0], r[1])),
  multiply(generators.innerProduct, mod(l[0] * r[1])),
);
const R = add(
  add(multiply(generators.G[0], l[1]), multiply(hPrime[1], r[0])),
  multiply(generators.innerProduct, mod(l[1] * r[0])),
);
const ipaChallenge = deriveScalar(
  DOMAIN,
  CONTEXT,
  "03",
  pointHex(commitment),
  pointHex(A),
  pointHex(S),
  pointHex(T1),
  pointHex(T2),
  toHex(tHat),
  toHex(tauX),
  toHex(mu),
  pointHex(unblindedPCommitment),
  pointHex(L),
  pointHex(R),
);
const ipaChallengeInverse = scalarInverse(ipaChallenge);
const ipaFinalA = mod(l[0] * ipaChallenge + l[1] * ipaChallengeInverse);
const ipaFinalB = mod(r[0] * ipaChallengeInverse + r[1] * ipaChallenge);

const proof = Object.freeze({
  A,
  S,
  T1,
  T2,
  tHat,
  tauX,
  mu,
  L,
  R,
  a: ipaFinalA,
  b: ipaFinalB,
});

const verifyScalar = (valueToCheck) =>
  typeof valueToCheck === "bigint" && valueToCheck >= 0n && valueToCheck < N;

export function verifyBulletproofRangeProof(
  fixture = bulletproofRangeProofFixture,
) {
  const { commitment: statement, generators: fixtureGenerators } = fixture;
  const candidate = fixture.proof;
  if (
    !statement ||
    !candidate ||
    !fixtureGenerators ||
    !Array.isArray(fixtureGenerators.G) ||
    !Array.isArray(fixtureGenerators.H) ||
    fixtureGenerators.G.length !== 2 ||
    fixtureGenerators.H.length !== 2
  ) {
    return false;
  }

  const allPoints = [
    statement,
    ...fixtureGenerators.G,
    ...fixtureGenerators.H,
    fixtureGenerators.value,
    fixtureGenerators.blinding,
    fixtureGenerators.innerProduct,
    candidate.A,
    candidate.S,
    candidate.T1,
    candidate.T2,
    candidate.L,
    candidate.R,
  ];
  if (!allPoints.every(validPoint)) return false;

  const allScalars = [
    candidate.tHat,
    candidate.tauX,
    candidate.mu,
    candidate.a,
    candidate.b,
  ];
  if (!allScalars.every(verifyScalar)) return false;

  const [g0, g1] = fixtureGenerators.G;
  const [h0, h1] = fixtureGenerators.H;
  const y = deriveScalar(
    DOMAIN,
    CONTEXT,
    pointHex(statement),
    pointHex(candidate.A),
    pointHex(candidate.S),
  );
  const z = deriveScalar(
    DOMAIN,
    CONTEXT,
    "01",
    toHex(y),
    pointHex(statement),
    pointHex(candidate.A),
    pointHex(candidate.S),
  );
  const x = deriveScalar(
    DOMAIN,
    CONTEXT,
    "02",
    toHex(y),
    toHex(z),
    pointHex(statement),
    pointHex(candidate.A),
    pointHex(candidate.S),
    pointHex(candidate.T1),
    pointHex(candidate.T2),
  );
  const hPrimeCandidate = [h0, multiply(h1, scalarInverse(y))];
  const deltaCandidate = mod((z - z * z) * (1n + y) - z * z * z * 3n);
  const tEquationLeft = add(
    multiply(fixtureGenerators.value, candidate.tHat),
    multiply(fixtureGenerators.blinding, candidate.tauX),
  );
  const tEquationRight = add(
    add(
      multiply(statement, z * z),
      multiply(fixtureGenerators.value, deltaCandidate),
    ),
    add(multiply(candidate.T1, x), multiply(candidate.T2, x * x)),
  );
  if (!pointEqual(tEquationLeft, tEquationRight)) return false;

  const pBaseCandidate = add(
    add(
      add(
        add(candidate.A, multiply(candidate.S, x)),
        negate(multiply(add(g0, g1), z)),
      ),
      multiscalar([z + z * z, z * y + z * z * 2n], hPrimeCandidate),
    ),
    negate(multiply(fixtureGenerators.blinding, candidate.mu)),
  );
  const pCandidate = add(
    pBaseCandidate,
    multiply(fixtureGenerators.innerProduct, candidate.tHat),
  );
  const u = deriveScalar(
    DOMAIN,
    CONTEXT,
    "03",
    pointHex(statement),
    pointHex(candidate.A),
    pointHex(candidate.S),
    pointHex(candidate.T1),
    pointHex(candidate.T2),
    toHex(candidate.tHat),
    toHex(candidate.tauX),
    toHex(candidate.mu),
    pointHex(pBaseCandidate),
    pointHex(candidate.L),
    pointHex(candidate.R),
  );
  const u2 = mod(u * u);
  const uInverse2 = mod(scalarInverse(u) * scalarInverse(u));
  const finalG = add(multiply(g0, scalarInverse(u)), multiply(g1, u));
  const finalH = add(
    multiply(hPrimeCandidate[0], u),
    multiply(hPrimeCandidate[1], scalarInverse(u)),
  );
  const ipaLeft = add(
    add(pCandidate, multiply(candidate.L, u2)),
    multiply(candidate.R, uInverse2),
  );
  const ipaRight = add(
    add(multiply(finalG, candidate.a), multiply(finalH, candidate.b)),
    multiply(fixtureGenerators.innerProduct, mod(candidate.a * candidate.b)),
  );
  return pointEqual(ipaLeft, ipaRight);
}

export const bulletproofRangeProofFixture = Object.freeze({
  domain: DOMAIN,
  context: CONTEXT,
  rangeBits: 2,
  commitment: Object.freeze(commitment),
  generators,
  proof,
  witness: Object.freeze({ value, blinding }),
  challenges: Object.freeze({
    y: challengeY,
    z: challengeZ,
    x: challengeX,
    ipa: ipaChallenge,
  }),
});

export function buildBulletproofContractArgs(
  fixture = bulletproofRangeProofFixture,
) {
  const { generators: fixtureGenerators } = fixture;
  const pointArgs = (point) => [point.x, point.y];
  return [
    hexToBin(fixture.domain),
    hexToBin(fixture.context),
    ...pointArgs(fixtureGenerators.value),
    ...pointArgs(fixtureGenerators.blinding),
    ...pointArgs(fixtureGenerators.innerProduct),
    ...fixtureGenerators.G.flatMap(pointArgs),
    ...fixtureGenerators.H.flatMap(pointArgs),
    ...pointArgs(fixture.commitment),
  ];
}

export function buildBulletproofProofArgs(
  fixture = bulletproofRangeProofFixture,
) {
  const { proof: fixtureProof, challenges } = fixture;
  const pointArgs = (point) => [point.x, point.y];
  return [
    challenges.y,
    challenges.z,
    challenges.x,
    challenges.ipa,
    fixtureProof.tHat,
    fixtureProof.tauX,
    fixtureProof.mu,
    fixtureProof.a,
    fixtureProof.b,
    ...pointArgs(fixtureProof.A),
    ...pointArgs(fixtureProof.S),
    ...pointArgs(fixtureProof.T1),
    ...pointArgs(fixtureProof.T2),
    ...pointArgs(fixtureProof.L),
    ...pointArgs(fixtureProof.R),
  ];
}

function linkedBulletproofStateFor(fixture) {
  const { proof: fixtureProof, challenges } = fixture;
  const state = [
    fixture.domain,
    fixture.context,
    toHex(challenges.y),
    toHex(challenges.z),
    toHex(challenges.x),
    toHex(challenges.ipa),
    toHex(fixtureProof.tHat),
    toHex(fixtureProof.tauX),
    toHex(fixtureProof.mu),
    toHex(fixtureProof.a),
    toHex(fixtureProof.b),
    pointHex(fixtureProof.A),
    pointHex(fixtureProof.S),
    pointHex(fixtureProof.T1),
    pointHex(fixtureProof.T2),
    pointHex(fixtureProof.L),
    pointHex(fixtureProof.R),
  ].join("");
  return sha256(hexToBin(state));
}

export function buildLinkedBulletproofProofArgs(
  fixture = bulletproofRangeProofFixture,
) {
  return [
    ...buildBulletproofProofArgs(fixture),
    linkedBulletproofStateFor(fixture),
  ];
}

export const invalidBulletproofRangeProofFixtures = Object.freeze({
  scalar: Object.freeze({
    ...bulletproofRangeProofFixture,
    proof: Object.freeze({
      ...proof,
      a: mod(proof.a + 1n),
    }),
  }),
  commitment: Object.freeze({
    ...bulletproofRangeProofFixture,
    commitment: Object.freeze(add(commitment, multiply(generators.value, 1n))),
  }),
  ipa: Object.freeze({
    ...bulletproofRangeProofFixture,
    proof: Object.freeze({
      ...proof,
      L: Object.freeze(negate(proof.L)),
    }),
  }),
});
