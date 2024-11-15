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


const BIT_128 = (1n << 128n) - 1n;

/**
 * Encrypts the input string using the IDEA algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the encrypted text
 */
export const encrypt: EncryptDecrypt = (text, key) => {
  /// Key resolution
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  const hashedKey = hash(resolvedKey) & BIT_128;

  /// Generation of key schedule
  const keySchedule = createKeySchedule(hashedKey, { inverse: false });

  const blocks = splitInto64BitBlocks(text);
  const outputs = blocks.map((b) => encryptBlock(b, keySchedule));

  const partialOutputMatrix: string[][] = [];
  const encryptedBlocks: bigint[] = [];

  /// Extract the partial outputs and the encrypted blocks.
  for (const [partialOutput, encryptedBlock] of outputs) {
    for (let i = 0; i < partialOutput.length; i++) {
      if (partialOutputMatrix[i] == null) {
        partialOutputMatrix[i] = [];
      }

      const [x1, x2, x3, x4] = partialOutput[i];
      const x1Str = x1.toString(16).padStart(8, "0").toUpperCase();
      const x2Str = x2.toString(16).padStart(8, "0").toUpperCase();
      const x3Str = x3.toString(16).padStart(8, "0").toUpperCase();
      const x4Str = x4.toString(16).padStart(8, "0").toUpperCase();

      partialOutputMatrix[i].push(`0x${x1Str} 0x${x2Str} 0x${x3Str} 0x${x4Str}`);
    }

    encryptedBlocks.push(encryptedBlock);
  }

  const encryptedText = extractStringFrom64BitBlocks(encryptedBlocks);
  const partialOutputs: string[] = [];
  for (const row of partialOutputMatrix) {
    partialOutputs.push(row.join(",\t"));
  }

  return [partialOutputs, encryptedText, resolvedKey];
};

/**
 * Decrypts the input string using the IDEA algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the decrypted text
 */
export const decrypt: EncryptDecrypt = (text, key) => {
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  const hashedKey = hash(resolvedKey) & BIT_128;
  const keySchedule = createKeySchedule(hashedKey, { inverse: true });

  const blocks = splitInto64BitBlocks(text);
  const outputs = blocks.map((b) => decryptBlock(b, keySchedule));
  const partialOutputMatrix: string[][] = [];
  const decryptedBlocks: bigint[] = [];

  /// Extract the partial outputs and the encrypted blocks.
  for (const [partialOutput, decryptedBlock] of outputs) {
    for (let i = 0; i < partialOutput.length; i++) {
      if (partialOutputMatrix[i] == null) {
        partialOutputMatrix[i] = [];
      }

      const [x1, x2, x3, x4] = partialOutput[i];
      const x1Str = x1.toString(16).padStart(8, "0").toUpperCase();
      const x2Str = x2.toString(16).padStart(8, "0").toUpperCase();
      const x3Str = x3.toString(16).padStart(8, "0").toUpperCase();
      const x4Str = x4.toString(16).padStart(8, "0").toUpperCase();

      partialOutputMatrix[i].push(`0x${x1Str} 0x${x2Str} 0x${x3Str} 0x${x4Str}`);
    }

    decryptedBlocks.push(decryptedBlock);
  }

  const decryptedText = extractStringFrom64BitBlocks(decryptedBlocks);
  const partialOutputs: string[] = [];
  for (const row of partialOutputMatrix) {
    partialOutputs.push(row.join(",\t"));
  }


  return [partialOutputs, decryptedText, resolvedKey];
};

type EncryptDecrypt = (text: string, key?: string) =>//
  [partialOutputs: string[], finalOutput: string, key: string];

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
        contiguousKeys[i - 3],
        contiguousKeys[i - 2],
        contiguousKeys[i - 1],
        contiguousKeys[i],
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
 * Takes the difference of two big integers modulo 2^16.
 * @param left the left operand
 * @param right the right operand
 * @returns the difference of two operands module 2^16
 */
const subtract = (left: bigint, right: bigint): bigint => {
  return add(left, additiveInverse(right));
};

/**
 * Multiplies two big integers modulo 2^16 + 1.
 * This follows the property that range(a mod b) = [0, b).
 * @param left the left operand
 * @param right the right operand
 * @returns the product of the two operands modulo 2^16 + 1
 */
const multiply = (left: bigint, right: bigint): bigint => {
  const initialResult = (left * right) % ((1n << 16n) + 1n);

  return initialResult < 0n //
    ? initialResult + ((1n << 16n) + 1n)
    : initialResult;
};

/**
 * Takes the division of two big integers modulo 2^16 + 1.
 * @param left the left operand
 * @param right the right operand
 * @returns the product of the inverse of the right operand and the left operand modulo 2^16 + 1
 */
const divide = (left: bigint, right: bigint): bigint => {
  return multiply(left, multiplicativeInverse(right));
};

/**
 * Returns the additive inverse of a value mod 2^16.
 * @param value the value to find the additive inverse of
 * @returns the additive inverse of the value mod 2^16
 */
const additiveInverse = (value: bigint): bigint => (0x10000n - value) % 0x10000n;

/**
 * Returns the multiplicative inverse of a value mod (2^16 + 1).
 * @param value the value to find the multiplicative inverse of
 * @returns the multiplicative inverse of the value mod (2^16 + 1)
 */
const multiplicativeInverse = (value: bigint): bigint => {
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
    throw new Error("Value is not invertible.");
  }

  return t < 0n ? t + 0x10001n : t;
};

type EncryptDecryptBlock = (block: bigint, keySchedule: bigint[][]) => //
  [[bigint, bigint, bigint, bigint][], bigint];

/**
 * Encrypts a block of data using the IDEA algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const encryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: [bigint, bigint, bigint, bigint][] = [];

  let [x1, x2, x3, x4] = extractBitsIntoBlocks(block, 16n, 4n);
  partialOutputs.push([x1, x2, x3, x4]);

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
    partialOutputs.push([x1, x2, x3, x4]);
  }

  // Round 8.5.
  const [z1, z2, z3, z4] = keySchedule[8];
  const y1 = multiply(x1, z1);
  const y2 = add(x2, z2);
  const y3 = add(x3, z3);
  const y4 = multiply(x4, z4);
  partialOutputs.push([y1, y2, y3, y4]);

  return [partialOutputs, (y1 << 48n) | (y2 << 32n) | (y3 << 16n) | y4];
};

/**
 * Encrypts a block of data using the IDEA algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const decryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: [bigint, bigint, bigint, bigint][] = [];

  let [x1, x2, x3, x4] = extractBitsIntoBlocks(block, 16n, 4n);
  partialOutputs.push([x1, x2, x3, x4]);

  for (let i = 0; i < 8; ++i) {
    const [z1, z2, z3, z4, z5, z6] = keySchedule[i];

    //  1. Multiply X1 and the inverse of first subkey Z1.
    const y1 = divide(x1, z1);
    //  2. Add X2 and the inverse of second subkey Z2.
    const y2 = subtract(x2, z2);
    //  3. Add X3 and the inverse of third subkey Z3.
    const y3 = subtract(x3, z3);
    //  4. Multiply X4 and the inverse of fourth subkey Z4.
    const y4 = divide(x4, z4);
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
    partialOutputs.push([x1, x2, x3, x4]);
  }

  // Round 8.5.
  const [z1, z2, z3, z4] = keySchedule[8];
  const y1 = divide(x1, z1);
  const y2 = subtract(x2, z2);
  const y3 = subtract(x3, z3);
  const y4 = divide(x4, z4);
  partialOutputs.push([y1, y2, y3, y4]);

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

/**
 * Takes a string and partitions it into 64-bit blocks of data.
 * @param text input string
 * @returns a sequence of 64-bit blocks of data.
 */
const splitInto64BitBlocks = (text: string): bigint[] => {
  let bits = 0n;
  for (let i = 0; i < text.length; i++) {
    bits <<= 8n;
    bits += BigInt(text.charCodeAt(i));
  }

  return extractBitsIntoBlocks(bits, 64n);
};

/**
 * This function concatenates the 64-bit blocks of data into a string.
 * @param blocks a sequence of 64-bit blocks of data.
 * @returns output string.
 */
const extractStringFrom64BitBlocks = (blocks: bigint[]): string => {
  let text = "";

  for (const block of blocks) {
    let extracted = "";
    let bits = block;
    while (bits > 0) {
      extracted = String.fromCharCode(Number(bits & 0xffn)) + extracted;
      bits >>= 8n;
    }
    text += extracted;
  }

  return text;
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
 * Generates a random 64-bit key.
 * @returns a random 64-bit key.
 */
const random64BitKey = (): number => {
  return Math.floor(Math.random() * 2 ** 61);
};
