import { hashKeyBySHA256 } from "../utils";

/**
 * This is an implementation of the Data Encryption Standard (DES) algorithm.
 * The DES algorithm is a symmetric-key algorithm for the encryption of digital data.
 * The reference used for this implementation is accessible in this document:
 *   https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
 */

/**
 * Encrypts the input string using the DES algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the encrypted text
 */
export const encrypt: EncryptDecrypt = async (text, key) => {
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  const hashedKey = await hashKeyBySHA256(resolvedKey);
  const keySchedule = createKeySchedule(hashedKey);

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

      const [l, r] = partialOutput[i];
      const lStr = l.toString(16).padStart(8, "0").toUpperCase();
      const rStr = r.toString(16).padStart(8, "0").toUpperCase();

      partialOutputMatrix[i].push(`0x${lStr} 0x${rStr}`);
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
 * Decrypts the input string using the DES algorithm.
 * @param text the input string
 * @param key a string key
 * @returns the decrypted text
 */
export const decrypt: EncryptDecrypt = async (text, key) => {
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  const hashedKey = await hashKeyBySHA256(resolvedKey);
  const keySchedule = createKeySchedule(hashedKey);

  const bits = splitInto64BitBlocks(text);
  const outputs = bits.map((b) => decryptBlock(b, keySchedule));

  const partialOutputMatrix: string[][] = [];
  const decryptedBlocks: bigint[] = [];
  for (const [partialOutput, decryptedBlock] of outputs) {
    for (let i = 0; i < partialOutput.length; i++) {
      if (partialOutputMatrix[i] == null) {
        partialOutputMatrix[i] = [];
      }

      const [l, r] = partialOutput[i];
      const lStr = l.toString(16).padStart(8, "0").toUpperCase();
      const rStr = r.toString(16).padStart(8, "0").toUpperCase();

      partialOutputMatrix[i].push(`0x${lStr} 0x${rStr}`);
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

type EncryptDecrypt = (
  text: string,
  key?: string
) => Promise<[partialOutputs: string[], finalOutput: string, key: string]>;

/**
 * These are the built-in tables used in the DES algorithm.
 * The tables are 1-indexed.
 */
const BUILTIN = {
  IP: [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
    56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53,
    45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
  ],

  IPInverse: [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
    5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
    42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
  ],

  P: [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
    30, 6, 22, 11, 4, 25,
  ],

  ESelection: [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19,
    20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
  ],

  s1: [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  ],

  s2: [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  ],

  s3: [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  ],

  s4: [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  ],

  s5: [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  ],

  s6: [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  ],

  s7: [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  ],

  s8: [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ],

  get sTables(): number[][][] {
    return [this.s1, this.s2, this.s3, this.s4, this.s5, this.s6, this.s7, this.s8];
  },

  pc1: [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 28, 20, 12, 4,
  ],

  pc2: [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
  ],

  shiftAmounts: [0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1],
};

/**
 * This shifts the block of data cyclicly to the left by the specified amount.
 * @param block Block of data to shift.
 * @param blockSize The amount of bits in the block to be used for truncation.
 * @param shiftAmount Amounts of bits to cyclicly shift
 * @returns The shifted data.
 */
const cyclicLeftShift = (block: bigint, blockSize: bigint, shiftAmount: bigint) =>
  ((block << BigInt(shiftAmount)) | (block >> BigInt(blockSize - shiftAmount))) &
  ((1n << BigInt(blockSize)) - 1n);


type EncryptDecryptBlock = (block: bigint, keySchedule: bigint[]) => [[bigint, bigint][], bigint];

/**
 * Encrypts a block of data using the DES algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const encryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: [bigint, bigint][] = [];
  let [l, r] = permuteSplit(block, BUILTIN.IP);

  partialOutputs.push([l, r]);
  for (let i = 0; i < 16; ++i) {
    [l, r] = [r, l ^ cipher(r, keySchedule[i])];

    partialOutputs.push([l, r]);
  }

  return [partialOutputs, permuteJoin(l, r, BUILTIN.IPInverse)];
};

/**
 * Decrypts a block of data using the DES algorithm.
 * @param block A block of 64-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The decrypted block of data.
 */
const decryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: [bigint, bigint][] = [];
  let [l, r] = permuteSplit(block, BUILTIN.IP);

  partialOutputs.push([l, r]);
  for (let i = 15; i >= 0; --i) {
    [l, r] = [r ^ cipher(l, keySchedule[i]), l];
    partialOutputs.push([l, r]);
  }

  return [partialOutputs, permuteJoin(l, r, BUILTIN.IPInverse)];
}

/**
 * "Let E denote a function which takes a block of 32 bits as input
 *  and yields a block of 48 bits as output."
 * @param block a 64-bit block of data.
 * @returns The selected 48-bit block of data.
 */
const selectE = (block: bigint): bigint => {
  let selected = 0n;
  for (let i = 0; i < BUILTIN.ESelection.length; i++) {
    selected <<= 1n;
    selected |= (block >> BigInt(BUILTIN.ESelection[i] - 1)) & 1n;
  }

  return selected;
};

/**
 * "Each of the unique selection functions S1,S2,...,S8, takes a 6-bit block
 *    as input and yields a 4-bit block as output".
 * @param block a 6-bit block of data.
 * @returns a 4-bit block of data.
 */
const selectS = (block: bigint, tableIndex: number): bigint => {
  const firstBit = (block & 0b100000n) >> 5n;
  const lastBit = block & 0b1n;
  const i = (firstBit << 1n) | lastBit;
  const j = (block & 0b011110n) >> 1n;

  return BigInt(BUILTIN.sTables[tableIndex][Number(i)][Number(j)]);
};

/**
 * Permutes the block of data as specified in the table. The table must be 1-indexed.
 * Values in the table need not to be unique.
 * @param block block of data to permute.
 * @param table an array of indices to permute the block of data with.
 * @returns the permuted block of data.
 */
const permute = (block: bigint, table: number[]): bigint => {
  let permuted = 0n;
  for (let i = 0; i < table.length; i++) {
    permuted <<= 1n;
    permuted |= (block >> BigInt(table[i] - 1)) & 1n;
  }

  return permuted;
};

/**
 * Permutes the block of data with the given table, and splits the result by half
 * into two 32-bit blocks.
 * @param block 64-bit block of data.
 * @param table an array of indices to permute the block with.
 * @returns a tuple of two 32-bit blocks.
 */
const permuteSplit = (block: bigint, table: number[]): [bigint, bigint] => {
  const permuted = permute(block, table);

  const l = permuted >> 32n;
  const r = permuted & 0xFFFFFFFFn;

  return [l, r];
};

/**
 * Combines [l] and [r] and permutes the result with the given table.
 * @param l a 32-block of data.
 * @param r a 32-block fo data.
 * @param table an array of indices to permute the block with.
 * @returns a 64-bit block of data.
 */
const permuteJoin = (l: bigint, r: bigint, table: number[]): bigint => {
  const combined = (l << 32n) | r;

  return permute(combined, table);
};

/**
 * Extracts the bits of a block of data into blocks of data of the specified size.
 * Since the block of data is in a numeric format, the output[0] is automatically zero-padded.
 * @param block a block of data.
 * @param blockSize the size of each block.
 * @returns a list of the blocks of data.
 */
const extractBitsIntoBlocks = (block: bigint, blockSize: number): bigint[] => {
  const shiftAmount = BigInt(blockSize);
  const blocks: bigint[] = [];
  while (block > 0) {
    blocks.unshift(block & ((1n << shiftAmount) - 1n));
    block >>= shiftAmount;
  }

  return blocks;
};

/**
 *
 * @param block a 32-bit block of data. Formally R.
 * @param key a 48-bit key from the key schedule. Formally K.
 * @returns a 32-bit block of data.
 */
const cipher = (block: bigint, key: bigint): bigint => {
  const selected = selectE(block);
  const xored = selected ^ key;
  const sixBitBlocks = extractBitsIntoBlocks(xored, 6);
  const sSelected = sixBitBlocks.map((b, i) => selectS(b, i));
  const concatenated = sSelected.reduce((accumulated, b) => (accumulated << 4n) | b, 0n);
  const permuted = permute(concatenated, BUILTIN.P);

  return permuted;
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

  return extractBitsIntoBlocks(bits, 64);
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
 * Generates the key schedule from the DES algorithm.
 * @param key The key to generate the key schedule from.
 * @returns sequence of 48-bit keys.
 */
const createKeySchedule = (key: bigint): bigint[] => {
  const [c, d] = permuteSplit(key, BUILTIN.pc1);
  const separatedKeySchedule: [c: bigint, d: bigint][] = [[c, d]];

  for (let i = 1; i <= 16; ++i) {
    const shiftAmount = BigInt(BUILTIN.shiftAmounts[i]);
    const cI = cyclicLeftShift(separatedKeySchedule[i - 1][0], 28n, shiftAmount);
    const dI = cyclicLeftShift(separatedKeySchedule[i - 1][1], 28n, shiftAmount);

    separatedKeySchedule.push([cI, dI]);
  }

  return separatedKeySchedule.slice(1).map(([c, d]) => permuteJoin(c, d, BUILTIN.pc2));
};

/**
 * Generates a random 64-bit key.
 * @returns a random 64-bit key.
 */
const random64BitKey = (): number => {
  return Math.floor(Math.random() * 2 ** 61);
};
