import { hexToBin } from "@bitauth/libauth";
import { sha256 } from "@cashscript/utils";

const bytes = (hex) => hexToBin(hex);
const domainTag = bytes(
  "7f1e4d2a9b083c516a77e1d2f09b4c6d3a8f215e6c4b9d0172e5a6c8f0b3d4e5",
);
const initialState = bytes(
  "1111111111111111111111111111111111111111111111111111111111111111",
);
const join = (...parts) => new Uint8Array(parts.flatMap((part) => [...part]));
const middleState = sha256(join(domainTag, initialState, bytes("00")));
const finalState = sha256(join(domainTag, middleState, bytes("01")));

export const linkedStateFixture = Object.freeze({
  domainTag,
  initialState,
  middleState,
  finalState,
});

export const invalidLinkedStateFixtures = Object.freeze({
  middleState: bytes(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ),
  finalState: bytes(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  ),
});

export function buildLinkedStateContractArgs(fixture = linkedStateFixture) {
  return [fixture.domainTag, fixture.initialState, fixture.finalState];
}

export function buildLinkedStateStepArgs(currentState, nextState) {
  return [currentState, nextState];
}
