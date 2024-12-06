
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

import { EncryptDecrypt, hashKeyBySHA256 } from "./utils";


const BIT_128 = (1n << 128n) - 1n;

/**
 * Encrypts the input string using the IDEA algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the encrypted text
 */
export const encrypt: EncryptDecrypt = async (messageHex, key, _) => {
  /// Key resolution
  const hashedKey = await hashKeyBySHA256(key) & BIT_128;
  const keySchedule = createKeySchedule(hashedKey, { inverse: false });

  /// Encryption of the blocks
  const blocks = extract64BitBlocksFromBLOB(messageHex);
  const outputs = blocks.map((b) => encryptBlock(b, keySchedule));
  const encryptedText = extractBLOBFrom64BitBlocks(outputs);

  return encryptedText;
};

/**
 * Decrypts the input string using the IDEA algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the decrypted text
 */
export const decrypt: EncryptDecrypt = async (messageHex, key, _) => {
  /// Key resolution
  const hashedKey = await hashKeyBySHA256(key) & BIT_128;
  const keySchedule = createKeySchedule(hashedKey, { inverse: true });

  /// Decryption of the blocks
  const blocks = extract64BitBlocksFromBLOB(messageHex);
  const outputs = blocks.map((b) => decryptBlock(b, keySchedule));
  const decryptedText = extractBLOBFrom64BitBlocks(outputs);

  return decryptedText;
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
const createKeySchedule = (key: bigint, { inverse }: { inverse: boolean }): bigint[][] => {
  let keyBits = key;
  const contiguousKeys: bigint[] = [];

  while (contiguousKeys.length < 52) {
    const subKeys = extractBitsIntoBlocks(keyBits, 16n);
    for (const subKey of subKeys) {
      if (contiguousKeys.length < 52) {
        contiguousKeys.push(subKey);
      }
    }

    keyBits = cyclicLeftShift(keyBits, 128n, 25n);
  }

  if (inverse) {
    const groups: bigint[][] = [];

    for (let i = contiguousKeys.length - 1; i >= 0; i -= 6) {
      groups.push([
        multiplicativeInverse(contiguousKeys[i - 3]),
        additiveInverse(contiguousKeys[i - 2]),
        additiveInverse(contiguousKeys[i - 1]),
        multiplicativeInverse(contiguousKeys[i]),
        contiguousKeys[i - 5],
        contiguousKeys[i - 4],
      ].filter((s) => s != null));
    }

    return groups;
  } else {
    const groups: bigint[][] = [];

    for (let i = 0; i < contiguousKeys.length; i += 6) {
      groups.push([
        contiguousKeys[i],
        contiguousKeys[i + 1],
        contiguousKeys[i + 2],
        contiguousKeys[i + 3],
        contiguousKeys[i + 4],
        contiguousKeys[i + 5],
      ].filter((s) => s != null));

    }
    return groups;
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
 *  This utilizes the extended euclidean algorithm for finding the multiplicative inverse.
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
  bigint;

/**
 * Encrypts a block of data using the IDEA algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const encryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  let [x1, x2, x3, x4] = extractBitsIntoBlocks(block, 16n, 4n);

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
  }

  // Round 8.5.
  const [z1, z2, z3, z4] = keySchedule[8];
  const y1 = multiply(x1, z1);
  const y2 = add(x2, z2);
  const y3 = add(x3, z3);
  const y4 = multiply(x4, z4);

  return (y1 << 48n) | (y2 << 32n) | (y3 << 16n) | y4;
};

/**
 * Encrypts a block of data using the IDEA algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const decryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  let [x1, x2, x3, x4] = extractBitsIntoBlocks(block, 16n, 4n);

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
  }

  // Round 8.5.
  const [z1, z2, z3, z4] = keySchedule[8];
  const y1 = multiply(x1, z1);
  const y2 = add(x2, z2);
  const y3 = add(x3, z3);
  const y4 = multiply(x4, z4);

  return (y1 << 48n) | (y2 << 32n) | (y3 << 16n) | y4;
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

const extract64BitBlocksFromBLOB = (hex: bigint): bigint[] => {
  const blocks: bigint[] = [];
  while (hex > 0) {
    blocks.unshift(hex & ((1n << 64n) - 1n));
    hex >>= 64n;
  }

  return blocks;
};

const extractBLOBFrom64BitBlocks = (blocks: bigint[]): bigint => {
  let hex = 0n;

  for (const block of blocks) {
    hex <<= 64n;
    hex |= block;
  }

  return hex;
};

/**
 * Based off the code at this post from user <b>sfussenegger</b>:
 *  https://stackoverflow.com/questions/1660501/what-is-a-good-64bit-hash-function-in-java-for-textual-strings
 * @param string input string
 * @returns a hash of the input string.
 */
const hash = (string: string): bigint => {
  let h = 1125899906842597n; // prime
  const len = string.length;

  for (let i = 0; i < len; i++) {
    h = 31n * h + BigInt(string.charCodeAt(i));
  }

  return h;
};

/**
 * Generates a random 128-bit key.
 * @returns a random 128-bit key.
 */
const random128BitKey = (): string => {
  return Math.floor((Math.random() + (10 ** 16)) * 10).toString();
};
