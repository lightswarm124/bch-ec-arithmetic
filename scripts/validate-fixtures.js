#!/usr/bin/env node
'use strict';

/**
 * Validate EC math fixture files against the published @bitauth/libauth
 * secp256k1 implementation.
 */

const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');
const { isDeepStrictEqual } = require('node:util');

const P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');

const KNOWN_OPCODES = new Set([
  'OP_ECADD',
  'OP_ECMUL',
  'OP_MODINV',
  'OP_ECMULTGEN',
  'OP_ECMULTMULTI',
]);

function parseArgs(argv) {
  const result = {
    fixturesRoot: 'fixtures',
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
    'Usage: validate-fixtures.js [--fixtures-root PATH] [--libauth-package-root PATH]',
  );
  process.exit(0);
}

function isHex32(value) {
  return typeof value === 'string' && value.length === 64 && /^[0-9a-f]+$/iu.test(value);
}

function hexToBytes32(value) {
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

function bytes32ToBigInt(bytes) {
  return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
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
  bytes.set(hexToBytes32(bigIntToHex32(point.x)), 1);
  bytes.set(hexToBytes32(bigIntToHex32(point.y)), 33);
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

function parseFieldElement(name, value) {
  if (!isHex32(value)) {
    throw new Error(`${name} must be a 32-byte hex string`);
  }
  const parsed = BigInt(`0x${value}`);
  if (parsed >= P) {
    throw new Error('field element >= p');
  }
  return parsed;
}

function parsePoint(prefix, inputObj, secp256k1) {
  const x = parseFieldElement(`${prefix}_x`, inputObj[`${prefix}_x`]);
  const y = parseFieldElement(`${prefix}_y`, inputObj[`${prefix}_y`]);
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

function parseScalarHex(value, secp256k1) {
  if (!isHex32(value)) {
    throw new Error('scalar must be a 32-byte hex string');
  }
  const bytes = hexToBytes32(value);
  if (!secp256k1.validatePrivateKey(bytes)) {
    throw new Error('scalar out of range');
  }
  return bytes;
}

function pointToOutput(point) {
  return {
    result_x: bigIntToHex32(point.x),
    result_y: bigIntToHex32(point.y),
  };
}

function evaluateOpcode(opcode, inputObj, secp256k1) {
  if (opcode === 'OP_ECADD') {
    const left = parsePoint('pointA', inputObj, secp256k1).point;
    const right = parsePoint('pointB', inputObj, secp256k1).point;
    const result = pointAdd(left, right);
    if (result === null) {
      throw new Error('point at infinity');
    }
    return pointToOutput(result);
  }

  if (opcode === 'OP_ECMUL') {
    const scalar = parseScalarHex(inputObj.scalar, secp256k1);
    const { uncompressed } = parsePoint('point', inputObj, secp256k1);
    const result = secp256k1.mulTweakPublicKeyUncompressed(uncompressed, scalar);
    if (typeof result === 'string') {
      throw new Error(result);
    }
    return pointToOutput(pointFromUncompressed(result));
  }

  if (opcode === 'OP_MODINV') {
    const value = parseFieldElement('value', inputObj.value);
    if (value === 0n) {
      throw new Error('value out of range');
    }
    return {
      inverse: bigIntToHex32(modInverse(value, P)),
    };
  }

  if (opcode === 'OP_ECMULTGEN') {
    const scalar = parseScalarHex(inputObj.scalar, secp256k1);
    const result = secp256k1.derivePublicKeyUncompressed(scalar);
    if (typeof result === 'string') {
      throw new Error(result);
    }
    return pointToOutput(pointFromUncompressed(result));
  }

  if (opcode === 'OP_ECMULTMULTI') {
    const { count, terms } = inputObj;
    if (!Number.isInteger(count) || count <= 0) {
      throw new Error('count must be nonzero');
    }
    if (!Array.isArray(terms) || terms.length !== count) {
      throw new Error('term count mismatch');
    }

    let total = null;
    for (const term of terms) {
      if (typeof term !== 'object' || term === null || Array.isArray(term)) {
        throw new Error('term must be an object');
      }
      const scalar = parseScalarHex(term.scalar, secp256k1);
      const { uncompressed } = parsePoint('point', term, secp256k1);
      const multiplied = secp256k1.mulTweakPublicKeyUncompressed(uncompressed, scalar);
      if (typeof multiplied === 'string') {
        throw new Error(multiplied);
      }
      total = pointAdd(total, pointFromUncompressed(multiplied));
    }

    if (total === null) {
      throw new Error('point at infinity');
    }
    return pointToOutput(total);
  }

  throw new Error(`unsupported opcode ${opcode}`);
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

  if (data.schema !== 'ecmath.spec-fixtures/v1') {
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

function validateFixture(pathname, data, secp256k1) {
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

    for (const key of ['id', 'description', 'input', 'expect']) {
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
    if (success && !('output' in testCase.expect)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} success cases must include output`);
    }
    if (!success && !('error' in testCase.expect)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} failure cases must include error`);
    }

    if (typeof testCase.input !== 'object' || testCase.input === null || Array.isArray(testCase.input)) {
      errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} input must be an object`);
      continue;
    }

    const input = testCase.input;
    if (data.opcode === 'OP_ECMULTMULTI') {
      if (!Array.isArray(input.terms)) {
        errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} terms must be an array`);
      } else {
        for (const [index, term] of input.terms.entries()) {
          if (typeof term !== 'object' || term === null || Array.isArray(term)) {
            errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} term ${index} must be an object`);
            continue;
          }
          for (const key of ['scalar', 'point_x', 'point_y']) {
            if (!isHex32(term[key])) {
              errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} term ${index} invalid ${key}`);
            }
          }
        }
      }
    } else if (data.opcode === 'OP_MODINV') {
      if (!isHex32(input.value)) {
        errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} invalid value`);
      }
    } else if (data.opcode === 'OP_ECMULTGEN') {
      if (!isHex32(input.scalar)) {
        errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} invalid scalar`);
      }
    } else if (data.opcode === 'OP_ECMUL') {
      if (!isHex32(input.scalar)) {
        errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} invalid scalar`);
      }
      for (const key of ['point_x', 'point_y']) {
        if (!isHex32(input[key])) {
          errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} invalid ${key}`);
        }
      }
    } else if (data.opcode === 'OP_ECADD') {
      for (const key of ['pointA_x', 'pointA_y', 'pointB_x', 'pointB_y']) {
        if (!isHex32(input[key])) {
          errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} invalid ${key}`);
        }
      }
    }

    try {
      const actual = evaluateOpcode(data.opcode, input, secp256k1);
      if (!success) {
        errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} expected failure but evaluated successfully`);
      } else if (!isDeepStrictEqual(actual, testCase.expect.output)) {
        errors.push(
          `${pathname}: case ${JSON.stringify(testCase.id)} output mismatch: expected ${JSON.stringify(testCase.expect.output)}, got ${JSON.stringify(actual)}`,
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (success) {
        errors.push(`${pathname}: case ${JSON.stringify(testCase.id)} expected success but evaluation failed: ${message}`);
      } else if (message !== testCase.expect.error) {
        errors.push(
          `${pathname}: case ${JSON.stringify(testCase.id)} error mismatch: expected ${JSON.stringify(testCase.expect.error)}, got ${JSON.stringify(message)}`,
        );
      }
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
      if (entry.isFile() && entry.name === 'tests.json') {
        files.push(filePath);
      }
    }
  };

  visit(rootDir);
  files.sort((left, right) => left.localeCompare(right));
  return files;
}

async function loadLibauth(secp256k1PackageRoot) {
  if (secp256k1PackageRoot === undefined) {
    try {
      return await import('@bitauth/libauth');
    } catch (error) {
      throw new Error(
        'Unable to import @bitauth/libauth. Run `npm install` at the repo root, or pass --libauth-package-root to an npm prefix containing the package.',
      );
    }
  }

  const resolvedRoot = path.resolve(secp256k1PackageRoot);
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
    throw new Error(`no fixture files found under ${root}`);
  }

  const { secp256k1 } = await loadLibauth(args.libauthPackageRoot);
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
    errors.push(...validateFixture(file, data, secp256k1));
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
  console.log(`validated ${files.length} fixture files`);
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
