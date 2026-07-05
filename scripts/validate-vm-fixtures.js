#!/usr/bin/env node
'use strict';

/**
 * Validate VM-level EC math execution fixtures against the published
 * @bitauth/libauth BCH VM and secp256k1 implementation.
 */

const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const { isDeepStrictEqual } = require('node:util');

const P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');

const KNOWN_OPCODES = new Set(['OP_ECADD', 'OP_ECMUL']);

function parseArgs(argv) {
  const result = {
    fixturesRoot: 'fixtures/vm',
    libauthPackageRoot: undefined,
  };

  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--fixtures-root') {
      index += 1;
      result.fixturesRoot = argv[index];
      continue;
    }
    if (arg.startsWith('--fixtures-root=')) {
      result.fixturesRoot = arg.slice('--fixtures-root='.length);
      continue;
    }
    if (arg === '--libauth-package-root') {
      index += 1;
      result.libauthPackageRoot = argv[index];
      continue;
    }
    if (arg.startsWith('--libauth-package-root=')) {
      result.libauthPackageRoot = arg.slice('--libauth-package-root='.length);
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      printHelpAndExit();
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return result;
}

function printHelpAndExit() {
  // eslint-disable-next-line no-console
  console.log(
    'Usage: validate-vm-fixtures.js [--fixtures-root PATH] [--libauth-package-root PATH]',
  );
  process.exit(0);
}

function isHex(value) {
  return typeof value === 'string' && value.length % 2 === 0 && /^[0-9a-f]*$/iu.test(value);
}

function hexToBytes(value) {
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function bytes32ToBigInt(bytes) {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function bigIntToHex32(value) {
  return value.toString(16).padStart(64, '0');
}

function mod(value, modulus) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modInverse(value, modulus) {
  let oldR = modulus;
  let r = mod(value, modulus);
  let oldT = 0n;
  let t = 1n;

  if (r === 0n) {
    throw new Error('value out of range');
  }

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldT, t] = [t, oldT - quotient * t];
  }

  if (oldR !== 1n) {
    throw new Error('value out of range');
  }

  return mod(oldT, modulus);
}

function isOnCurve(point) {
  const { x, y } = point;
  return mod(y * y - (x * x * x + 7n), P) === 0n;
}

function pointToUncompressed(point) {
  const bytes = new Uint8Array(65);
  bytes[0] = 0x04;
  bytes.set(hexToBytes(bigIntToHex32(point.x)), 1);
  bytes.set(hexToBytes(bigIntToHex32(point.y)), 33);
  return bytes;
}

function pointFromUncompressed(uncompressed) {
  if (
    !(uncompressed instanceof Uint8Array) ||
    uncompressed.length !== 65 ||
    uncompressed[0] !== 0x04
  ) {
    throw new Error('unexpected public key encoding');
  }
  return {
    x: bytes32ToBigInt(uncompressed.subarray(1, 33)),
    y: bytes32ToBigInt(uncompressed.subarray(33, 65)),
  };
}

function pointAdd(left, right) {
  if (left === null) {
    return right;
  }
  if (right === null) {
    return left;
  }

  const { x: x1, y: y1 } = left;
  const { x: x2, y: y2 } = right;

  if (x1 === x2 && mod(y1 + y2, P) === 0n) {
    return null;
  }

  let slope;
  if (x1 === x2 && y1 === y2) {
    if (y1 === 0n) {
      return null;
    }
    slope = mod((3n * x1 * x1) * modInverse(2n * y1, P), P);
  } else {
    if (x1 === x2) {
      throw new Error('invalid point pair');
    }
    slope = mod((y2 - y1) * modInverse(x2 - x1, P), P);
  }

  const x3 = mod(slope * slope - x1 - x2, P);
  const y3 = mod(slope * (x1 - x3) - y1, P);
  return { x: x3, y: y3 };
}

function parseFieldElementBytes(name, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(`${name} must be a 32-byte stack item`);
  }
  const parsed = bytes32ToBigInt(bytes);
  if (parsed >= P) {
    throw new Error('field element >= p');
  }
  return parsed;
}

function parseScalarBytes(bytes, secp256k1) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('scalar must be a 32-byte stack item');
  }
  if (!secp256k1.validatePrivateKey(bytes)) {
    throw new Error('scalar out of range');
  }
  return bytes;
}

function parsePointBytes(prefix, xBytes, yBytes, secp256k1) {
  const x = parseFieldElementBytes(`${prefix}_x`, xBytes);
  const y = parseFieldElementBytes(`${prefix}_y`, yBytes);
  const point = { x, y };
  if (!isOnCurve(point)) {
    throw new Error('point not on curve');
  }

  const uncompressed = pointToUncompressed(point);
  if (!secp256k1.validatePublicKey(uncompressed)) {
    throw new Error('point not on curve');
  }

  return { point, uncompressed };
}

function stackToTopFirst(state, binToHex) {
  return state.stack.slice().reverse().map((item) => binToHex(item));
}

function createEcMathInstructionSet(libauth) {
  const {
    AuthenticationErrorCommon,
    applyError,
    conditionallyEvaluate,
    createAuthenticationVirtualMachine,
    createInstructionSetBCH2023,
    incrementOperationCount,
    pushToStack,
    secp256k1,
  } = libauth;

  const wrap = (operation) => incrementOperationCount(conditionallyEvaluate(operation));

  const opEcAdd = (state) => {
    if (state.stack.length < 4) {
      return applyError(state, AuthenticationErrorCommon.emptyStack);
    }

    const [pointB_y, pointB_x, pointA_y, pointA_x] = state.stack.slice(-4).reverse();

    try {
      const left = parsePointBytes('pointA', pointA_x, pointA_y, secp256k1).point;
      const right = parsePointBytes('pointB', pointB_x, pointB_y, secp256k1).point;
      const result = pointAdd(left, right);
      if (result === null) {
        throw new Error('point at infinity');
      }

      state.stack.length -= 4;
      return pushToStack(
        state,
        hexToBytes(bigIntToHex32(result.x)),
        hexToBytes(bigIntToHex32(result.y)),
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return applyError(state, message);
    }
  };

  const opEcMul = (state) => {
    if (state.stack.length < 3) {
      return applyError(state, AuthenticationErrorCommon.emptyStack);
    }

    const [scalar, point_y, point_x] = state.stack.slice(-3).reverse();

    try {
      const scalarBytes = parseScalarBytes(scalar, secp256k1);
      const { uncompressed } = parsePointBytes('point', point_x, point_y, secp256k1);
      const result = secp256k1.mulTweakPublicKeyUncompressed(uncompressed, scalarBytes);
      if (typeof result === 'string') {
        throw new Error(result);
      }

      const { x, y } = pointFromUncompressed(result);
      state.stack.length -= 3;
      return pushToStack(state, hexToBytes(bigIntToHex32(x)), hexToBytes(bigIntToHex32(y)));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return applyError(state, message);
    }
  };

  const instructionSet = createInstructionSetBCH2023(false);
  instructionSet.operations[0xd6] = wrap(opEcAdd);
  instructionSet.operations[0xd7] = wrap(opEcMul);

  return createAuthenticationVirtualMachine(instructionSet);
}

function validateFixtureShape(pathname, data) {
  const errors = [];

  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return [`${pathname}: top-level value must be an object`];
  }

  for (const key of ['schema', 'curve', 'opcode', 'status', 'source', 'cases']) {
    if (!(key in data)) {
      errors.push(`${pathname}: missing top-level key ${JSON.stringify(key)}`);
    }
  }

  if (data.schema !== 'ecmath.vm-fixtures/v1') {
    errors.push(`${pathname}: unsupported schema ${JSON.stringify(data.schema)}`);
  }
  if (data.curve !== 'secp256k1') {
    errors.push(`${pathname}: unsupported curve ${JSON.stringify(data.curve)}`);
  }
  if (!KNOWN_OPCODES.has(data.opcode)) {
    errors.push(`${pathname}: unsupported opcode ${JSON.stringify(data.opcode)}`);
  }
  if (data.status !== 'core' && data.status !== 'proposed') {
    errors.push(`${pathname}: unsupported status ${JSON.stringify(data.status)}`);
  }
  if (typeof data.source !== 'string' || data.source.length === 0) {
    errors.push(`${pathname}: source must be a non-empty string`);
  }
  if (!Array.isArray(data.cases)) {
    errors.push(`${pathname}: cases must be an array`);
  }

  return errors;
}

function validateFixture(pathname, data, vm, binToHex, createTestAuthenticationProgramBCH) {
  const errors = validateFixtureShape(pathname, data);
  if (!Array.isArray(data.cases)) {
    return errors;
  }

  const seenIds = new Set();
  for (const testCase of data.cases) {
    if (typeof testCase !== 'object' || testCase === null || Array.isArray(testCase)) {
      errors.push(`${pathname}: each case must be an object`);
      continue;
    }

    for (const key of ['id', 'description', 'unlockingBytecode', 'lockingBytecode', 'expect']) {
      if (!(key in testCase)) {
        errors.push(`${pathname}: case missing key ${JSON.stringify(key)}`);
      }
    }

    if (typeof testCase.id !== 'string' || testCase.id.length === 0) {
      errors.push(`${pathname}: case id must be a non-empty string`);
      continue;
    }
    if (seenIds.has(testCase.id)) {
      errors.push(`${pathname}: duplicate case id ${JSON.stringify(testCase.id)}`);
      continue;
    }
    seenIds.add(testCase.id);

    if (
      typeof testCase.expect !== 'object' ||
      testCase.expect === null ||
      Array.isArray(testCase.expect) ||
      !('success' in testCase.expect)
    ) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} must include expect.success`);
      continue;
    }

    const success = testCase.expect.success === true;
    if (!('stack' in testCase.expect)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} must include expect.stack`);
    }
    if (success && !('stack' in testCase.expect)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} success cases must include expect.stack`);
    }
    if (!success && !('error' in testCase.expect)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} failure cases must include expect.error`);
    }

    if (typeof testCase.unlockingBytecode !== 'string' || !isHex(testCase.unlockingBytecode)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} unlockingBytecode must be hex`);
    }
    if (typeof testCase.lockingBytecode !== 'string' || !isHex(testCase.lockingBytecode)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} lockingBytecode must be hex`);
    }
    if (!Array.isArray(testCase.expect.stack)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} expect.stack must be an array`);
    } else {
      for (const [index, item] of testCase.expect.stack.entries()) {
        if (typeof item !== 'string' || !isHex(item)) {
          errors.push(
            `${pathname}: case ${JSON.stringify(testCase.id)} expect.stack item ${index} must be hex`,
          );
        }
      }
    }
    if (!success && typeof testCase.expect.error !== 'string') {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} expect.error must be a string`);
    }

    if (
      typeof testCase.unlockingBytecode !== 'string' ||
      !isHex(testCase.unlockingBytecode) ||
      typeof testCase.lockingBytecode !== 'string' ||
      !isHex(testCase.lockingBytecode) ||
      !Array.isArray(testCase.expect.stack) ||
      (!success && typeof testCase.expect.error !== 'string')
    ) {
      continue;
    }

    const createdProgram = createTestAuthenticationProgramBCH({
      lockingBytecode: hexToBytes(testCase.lockingBytecode),
      unlockingBytecode: hexToBytes(testCase.unlockingBytecode),
      valueSatoshis: 0n,
    });

    let evaluation;
    try {
      evaluation = vm.evaluate(createdProgram);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} evaluation threw: ${message}`);
      continue;
    }

    const actualStack = stackToTopFirst(evaluation, binToHex);
    if (success) {
      if (evaluation.error !== undefined) {
        errors.push(
          `${pathname}: case ${JSON.stringify(testCase.id)} expected success but evaluation failed: ${evaluation.error}`,
        );
      } else if (!isDeepStrictEqual(actualStack, testCase.expect.stack)) {
        errors.push(
          `${pathname}: case ${JSON.stringify(testCase.id)} stack mismatch: expected ${JSON.stringify(testCase.expect.stack)}, got ${JSON.stringify(actualStack)}`,
        );
      }
    } else if (evaluation.error !== testCase.expect.error) {
      errors.push(
        `${pathname}: case ${JSON.stringify(testCase.id)} error mismatch: expected ${JSON.stringify(testCase.expect.error)}, got ${JSON.stringify(evaluation.error)}`,
      );
    } else if (!isDeepStrictEqual(actualStack, testCase.expect.stack)) {
      errors.push(
        `${pathname}: case ${JSON.stringify(testCase.id)} stack mismatch: expected ${JSON.stringify(testCase.expect.stack)}, got ${JSON.stringify(actualStack)}`,
      );
    }
  }

  return errors;
}

function iterFixtureFiles(rootDir) {
  const files = [];

  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const filePath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(filePath);
        continue;
      }
      if (entry.isFile() && entry.name === 'execution.json') {
        files.push(filePath);
      }
    }
  };

  visit(rootDir);
  files.sort((left, right) => left.localeCompare(right));
  return files;
}

async function loadLibauth(libauthPackageRoot) {
  if (libauthPackageRoot === undefined) {
    try {
      return await import('@bitauth/libauth');
    } catch (error) {
      throw new Error(
        'Unable to import @bitauth/libauth. Run `npm install` at the repo root, or pass --libauth-package-root to an npm prefix containing the package.',
      );
    }
  }

  const resolvedRoot = path.resolve(libauthPackageRoot);
  const requireFromRoot = createRequire(path.join(resolvedRoot, '__resolver__.js'));
  const entryPoint = requireFromRoot.resolve('@bitauth/libauth');
  return import(pathToFileURL(entryPoint).href);
}

async function main() {
  const args = parseArgs(process.argv);
  const root = path.resolve(args.fixturesRoot);
  if (!fs.existsSync(root)) {
    throw new Error(`fixtures root not found: ${root}`);
  }

  const files = iterFixtureFiles(root);
  if (files.length === 0) {
    throw new Error(`no VM fixture files found under ${root}`);
  }

  const libauth = await loadLibauth(args.libauthPackageRoot);
  const vm = createEcMathInstructionSet(libauth);
  const errors = [];

  for (const file of files) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`${file}: invalid JSON: ${message}`);
      continue;
    }
    errors.push(
      ...validateFixture(
        file,
        data,
        vm,
        libauth.binToHex,
        libauth.createTestAuthenticationProgramBCH,
      ),
    );
  }

  if (errors.length > 0) {
    for (const error of errors) {
      // eslint-disable-next-line no-console
      console.error(error);
    }
    process.exitCode = 1;
    return;
  }

  // eslint-disable-next-line no-console
  console.log(`validated ${files.length} VM fixture files`);
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
