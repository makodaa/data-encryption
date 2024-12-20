
/**
 * IDEA (International Data Encryption Algorithm) is a symmetric key block cipher
 *   that operates on 64-bit blocks of data using a 128-bit key.
 * It consists of 8.5 rounds of encryption and decryption.
 * 
 * The IDEA algorithm is based on the following operations:
 *   - Addition modulo 2^16
 *   - Multiplication modulo 2^16 + 1
 *   - Bitwise XOR
 * 
 * The references used for this implementation are accessible in the documents:
 *   Hoffman, N. (2007). Cryptologia, 31(2), 143–151. doi:10.1080/01611190701215640
 * 
 *   Shehata, K., Hamdy, N., Elagooz, S., & Helmy, M. (2003). DESIGN AND IMPLEMENTATION OF IDEA ALGORITHM KEY SCHEDULE ON FPGA. Retrieved from https://asat.journals.ekb.eg/article_24692.html
 * 
 *   Lai, X., Massey, J.L. (1991). A Proposal for a New Block Encryption Standard. In: Damgård, I.B. (eds) Advances in Cryptology — EUROCRYPT ’90. EUROCRYPT 1990. Lecture Notes in Computer Science, vol 473. Springer, Berlin, Heidelberg. https://doi.org/10.1007/3-540-46877-3_35
 */

import { EncryptDecrypt, hashKeyBySHA256, PartialOutputs, wordHex } from "../utils";


const BIT_128 = (1n << 128n) - 1n;

/**
 * Encrypts the input string using the IDEA algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the encrypted text
 */
export const encrypt: EncryptDecrypt = async (messageHex, key, _) => {
  /// Output preparation
  const partialOutputs: [title: string, content: string][] = [];
  const encryptedBlocks: bigint[] = [];

  /// Key resolution
  const resolvedKey = key || random128BitKey();
  const hashedKey = await hashKeyBySHA256(resolvedKey) & BIT_128;

  /// Generation of key schedule
  const [pO, keySchedule] = createKeySchedule(hashedKey, { inverse: false });
  partialOutputs.push(...pO);

  const blocks = extract64BitBytesFromBLOB(messageHex);
  const outputs = blocks.map((b) => processBlock(b, keySchedule));

  /// Extract the partial outputs and the encrypted blocks.
  const initialLength = partialOutputs.length;
  for (const [partialOutput, encryptedBlock] of outputs) {
    for (let i = 0; i < partialOutput.length; i++) {
      if (partialOutputs[initialLength + i] == null) {
        partialOutputs[initialLength + i] = partialOutput[i];
      } else {
        partialOutputs[initialLength + i][1] += "\n " + partialOutput[i][1];
      }
    }
    encryptedBlocks.push(encryptedBlock);
  }
  const encryptedText = extractBLOBFrom64BitBytes(encryptedBlocks);
  return [partialOutputs, encryptedText, resolvedKey, hashedKey];
};

/**
 * Decrypts the input string using the IDEA algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the decrypted text
 */
export const decrypt: EncryptDecrypt = async (messageHex, key, _) => {
  /// Output preparation
  const partialOutputs: [title: string, content: string][] = [];
  const decryptedBlocks: bigint[] = [];

  /// Key resolution
  const resolvedKey = key || random128BitKey();
  const hashedKey = await hashKeyBySHA256(resolvedKey) & BIT_128;
  const [pO, keySchedule] = createKeySchedule(hashedKey, { inverse: true });
  partialOutputs.push(...pO);

  /// Decryption of the blocks
  const blocks = extract64BitBytesFromBLOB(messageHex);
  const outputs = blocks.map((b) => processBlock(b, keySchedule));

  /// Extract the partial outputs and the decrypted blocks.
  const initialLength = partialOutputs.length;
  for (const [partialOutput, decryptedBlock] of outputs) {
    for (let i = 0; i < partialOutput.length; i++) {
      if (partialOutputs[initialLength + i] == null) {
        partialOutputs[initialLength + i] = partialOutput[i];
      } else {
        partialOutputs[initialLength + i][1] += "\n " + partialOutput[i][1];
      }
    }
    decryptedBlocks.push(decryptedBlock);
  }

  const decryptedText = extractBLOBFrom64BitBytes(decryptedBlocks);

  return [partialOutputs, decryptedText, resolvedKey, hashedKey];
};

/**
 * Cyclically shifts a block to the left by the specified amount.
 *  Specifically, it shifts the block to the left by the specified amount
 *  and wraps around the block.
 * @param block the block to shift
 * @param blockSize the size of the block
 * @param shiftAmount the amount to shift the block
 * @returns the block shifted cyclically to the left by the specified amount
 */
const cyclicLeftShift = (block: bigint, blockSize: bigint, shiftAmount: bigint) =>
  ((block << shiftAmount) | (block >> (blockSize - shiftAmount))) &
  ((1n << blockSize) - 1n);

/**
 * Generates the key schedule for the IDEA algorithm.
 * @param key the key to generate the key schedule from.
 * @returns sequence of 6 subkeys for each round, and 4 subkeys for the half-round.
 */
const createKeySchedule = (key: bigint, { inverse }: { inverse: boolean }): 
  [PartialOutputs, bigint[][]] => {
  const partialOutputs: PartialOutputs = [];

  partialOutputs.push([
    `${inverse ? "Inverse " : ""}Key Schedule`,
    null,
  ]);

  let rotations = 0;
  let keyBits = key;
  const subkeys: bigint[] = [];
  while (subkeys.length < 52) {
    const subKeys = extractBitsIntoBlocks(keyBits, 16n);

    partialOutputs.push([
      `Rotated Key ${rotations++}`,
      keyBits.toString(16).padStart(32, "0"),
    ]);

    partialOutputs.push([
      `Subkeys ${subkeys.length + 1} to ` +
        `${Math.min(subkeys.length + 1 + subKeys.length - 1, 52)}`,
      subKeys.slice(0, Math.min(subKeys.length, 52 - subkeys.length)).map((s) => s.toString(16)).join(", "),
    ]);

    for (const subKey of subKeys) {
      if (subkeys.length < 52) {
        subkeys.push(subKey);
      }
    }

    keyBits = cyclicLeftShift(keyBits, 128n, 25n);
  }

  console.log(subkeys);
  if (inverse) {
    const groups: bigint[][] = [];

    for (let i = subkeys.length - 1; i >= 0; i -= 6) {
      groups.push([
        multiplicativeInverse(subkeys[i - 3]),
        additiveInverse(subkeys[i - 2]),
        additiveInverse(subkeys[i - 1]),
        multiplicativeInverse(subkeys[i]),
        subkeys[i - 5],
        subkeys[i - 4],
      ].filter((s) => s != null));
    }

    return [partialOutputs, groups];
  } else {
    const groups: bigint[][] = [];

    for (let i = 0; i < subkeys.length; i += 6) {
      groups.push([
        subkeys[i],
        subkeys[i + 1],
        subkeys[i + 2],
        subkeys[i + 3],
        subkeys[i + 4],
        subkeys[i + 5],
      ].filter((s) => s != null));

    }
    return [partialOutputs, groups];
  }
};

/**
 * Adds two big integers modulo 2^16.
 * @param left the left operand
 * @param right the right operand
 * @returns the sum of the two operands modulo 2^16
 */
const add = (left: bigint, right: bigint): bigint => {
  const initialResult = (left + right) % (1n << 16n);

  return initialResult < 0n //
    ? initialResult + (1n << 16n) //
    : initialResult;
};

/**
 * Multiplies two big integers modulo 2^16 + 1.
 * This follows the property that range(a mod b) = [0, b).
 * @param left the left operand
 * @param right the right operand
 * @returns the product of the two operands modulo 2^16 + 1
 */
const multiply = (left: bigint, right: bigint): bigint => {
  const result = left * right;
  if (result != 0n) {
    return (result % 0x10001n) & 0xFFFFn;
  }

  if (left != 0n || right != 0n) {
    return ((0x10001n - left - right) % 0x10001n) & 0xFFFFn;
  }
  return 1n;
};


/**
 * Returns the additive inverse of a value mod 2^16.
 * @param value the value to find the additive inverse of
 * @returns the additive inverse of the value mod 2^16
 */
const additiveInverse = (value: bigint): bigint => ((0x10000n - value) % 0x10000n) & 0xFFFFn;

/**
 * Returns the multiplicative inverse of a value mod (2^16 + 1).
 * @param value the value to find the multiplicative inverse of
 * @returns the multiplicative inverse of the value mod (2^16 + 1)
 */
const multiplicativeInverse = (value: bigint): bigint => {
  if (value <= 1n) {
    return value;
  }

  let t = 0n;
  let r = 0x10001n;
  let newT = 1n;
  let newR = value;

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (r > 1n) {
    throw new Error(`Value is not invertible. ${value}`);
  }

  return t < 0n ? t + 0x10001n : t;
};

type EncryptDecryptBlock = (block: bigint, keySchedule: bigint[][]) => //
  [[title: string, content: string][], bigint];

/**
 * Encrypts a block of data using the IDEA algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const processBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: [title: string, content: string][] = [];

  let [x1, x2, x3, x4] = extractBitsIntoBlocks(block, 16n, 4n);
  partialOutputs.push([
    `Splitting 64-bit block into 4 16-bit blocks`,
    `${wordHex(x1)}, ${wordHex(x2)}, ${wordHex(x3)}, ${wordHex(x4)}`,
  ]);

  for (let i = 0; i < 8; ++i) {
    const [z1, z2, z3, z4, z5, z6] = keySchedule[i];

    //  1. Multiply X1 and the first subkey Z1.
    const y1 = multiply(x1, z1);
    //  2. Add X2 and the second subkey Z2.
    const y2 = add(x2, z2);
    //  3. Add X3 and the third subkey Z3.
    const y3 = add(x3, z3);
    //  4. Multiply X4 and the fourth subkey Z4.
    const y4 = multiply(x4, z4);
    //  5. Bitwise XOR the results of steps 1 and 3.
    const y5 = y1 ^ y3;
    //  6. Bitwise XOR the results of steps 2 and 4.
    const y6 = y2 ^ y4;
    //  7. Multiply the result of step 5 and the fifth subkey Z5.
    const y7 = multiply(y5, z5);
    //  8. Add the results of steps 6 and 7.
    const y8 = add(y6, y7);
    //  9. Multiply the result of step 8 and the sixth subkey Z6.
    const y9 = multiply(y8, z6);
    //  10. Add the results of steps 7 and 9.
    const y10 = add(y7, y9);
    //  11. Bitwise XOR the results of steps 1 and 9.
    const y11 = y1 ^ y9;
    //  12. Bitwise XOR the results of steps 3 and 9.
    const y12 = y3 ^ y9;
    //  13. Bitwise XOR the results of steps 2 and 10.
    const y13 = y2 ^ y10;
    //  14. Bitwise XOR the results of steps 4 and 10
    const y14 = y4 ^ y10;

    [x1, x2, x3, x4] = [y11, y13, y12, y14];

    partialOutputs.push([
      `Round ${i + 1}`,
      `${wordHex(x1)}, ${wordHex(x2)}, ${wordHex(x3)}, ${wordHex(x4)}`,
    ]);
  }

  // Round 8.5.
  const [z1, z2, z3, z4] = keySchedule[8];
  const y1 = multiply(x1, z1);
  const y2 = add(x2, z2);
  const y3 = add(x3, z3);
  const y4 = multiply(x4, z4);
  partialOutputs.push([
    `Round 8.5`,
    `${wordHex(y1)}, ${wordHex(y2)}, ${wordHex(y3)}, ${wordHex(y4)}`,
  ]);

  return [partialOutputs, (y1 << 48n) | (y2 << 32n) | (y3 << 16n) | y4];
};

/**
 * Extracts the bits of a block of data into blocks of data of the specified size.
 * Since the block of data is in a numeric format, the output[0] is automatically zero-padded.
 * @param block a block of data.
 * @param blockSize the size of each block.
 * @returns a list of the blocks of data.
 */
const extractBitsIntoBlocks = (block: bigint, blockSize: bigint, blockCount?: bigint): bigint[] => {
  const blocks: bigint[] = [];
  while (block > 0 || (blockCount != null && blocks.length < blockCount)) {
    blocks.unshift(block & ((1n << blockSize) - 1n));
    block >>= blockSize;
  }

  return blocks;
};

const extract64BitBytesFromBLOB = (hex: bigint): bigint[] => {
  const blocks: bigint[] = [];
  while (hex > 0) {
    blocks.unshift(hex & ((1n << 64n) - 1n));
    hex >>= 64n;
  }

  return blocks;
};

const extractBLOBFrom64BitBytes = (blocks: bigint[]): bigint => {
  let hex = 0n;

  for (const block of blocks) {
    hex <<= 64n;
    hex |= block;
  }

  return hex;
};

/**
 * Generates a random 128-bit key.
 * @returns a random 128-bit key.
 */
const random128BitKey = (): string => {
  return Math.floor((Math.random() + (10 ** 16)) * 10).toString();
};
