import { hexToBin } from "@bitauth/libauth";

export const validEcFixtures = Object.freeze({
  ecmul: Object.freeze({
    scalar: `${"0".repeat(63)}2`,
    pointY: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    pointX: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    resultY: "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
    resultX: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  }),
  ecadd: Object.freeze({
    pointBy: "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
    pointBx: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    pointAy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    pointAx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    resultY: "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
    resultX: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  }),
  modinv: Object.freeze({
    value: `${"0".repeat(63)}2`,
    inverse: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
  }),
  ecmultgen: Object.freeze({
    scalar: `${"0".repeat(63)}2`,
    resultY: "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
    resultX: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  }),
  ecmultmulti: Object.freeze({
    count: 2n,
    scalarN: `${"0".repeat(63)}2`,
    pointNY: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    pointNX: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    scalar1: `${"0".repeat(63)}1`,
    point1Y: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    point1X: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    resultY: "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
    resultX: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  }),
});

export const invalidEcFixtures = Object.freeze({
  nonCanonicalEcmul: Object.freeze({
    ...validEcFixtures.ecmul,
    scalar: "02",
  }),
  zeroPoint: Object.freeze({
    ...validEcFixtures.ecmul,
    pointY: "0".repeat(64),
    pointX: "0".repeat(64),
  }),
  nonCanonicalModinv: Object.freeze({
    ...validEcFixtures.modinv,
    value: "02",
  }),
  invalidEcmultmultiCount: Object.freeze({
    ...validEcFixtures.ecmultmulti,
    count: 0n,
  }),
});

const bytes = (hex) => hexToBin(hex);

export function buildEcmulArgs(fixture = validEcFixtures.ecmul) {
  return [
    bytes(fixture.scalar),
    bytes(fixture.pointY),
    bytes(fixture.pointX),
    bytes(fixture.resultY),
    bytes(fixture.resultX),
  ];
}

export function buildEcaddArgs(fixture = validEcFixtures.ecadd) {
  return [
    bytes(fixture.pointBy),
    bytes(fixture.pointBx),
    bytes(fixture.pointAy),
    bytes(fixture.pointAx),
    bytes(fixture.resultY),
    bytes(fixture.resultX),
  ];
}

export function buildModinvArgs(fixture = validEcFixtures.modinv) {
  return [bytes(fixture.value), bytes(fixture.inverse)];
}

export function buildEcmultgenArgs(fixture = validEcFixtures.ecmultgen) {
  return [
    bytes(fixture.scalar),
    bytes(fixture.resultY),
    bytes(fixture.resultX),
  ];
}

export function buildEcmultmultiArgs(fixture = validEcFixtures.ecmultmulti) {
  return [
    fixture.count,
    bytes(fixture.scalarN),
    bytes(fixture.pointNY),
    bytes(fixture.pointNX),
    bytes(fixture.scalar1),
    bytes(fixture.point1Y),
    bytes(fixture.point1X),
    bytes(fixture.resultY),
    bytes(fixture.resultX),
  ];
}

export function buildAddendumArgs() {
  return [
    ...buildModinvArgs(),
    ...buildEcmultgenArgs(),
    ...buildEcmultmultiArgs(),
  ];
}
