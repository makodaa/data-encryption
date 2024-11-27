import { EncryptDecrypt, hashKeyBySHA256, random128BitKey } from "../utils";

export const encrypt: EncryptDecrypt = async (input: bigint, key?: string, nonce?: bigint) => {
  const resolvedKey = key || random128BitKey();
  const keyBytes = await hashKeyBySHA256(key);
  const messageBytes = extractBytesFromBlob(input);
  const [partialOutputs, outputStream] = xorKeyStream(messageBytes, keyBytes, nonce);
  const output = extractBlobFromBytes(outputStream);

  return [partialOutputs, output, resolvedKey];
};

export const decrypt: EncryptDecrypt = async (input: bigint, key?: string, nonce?: bigint) => {
  const resolvedKey = key || random128BitKey();
  const keyBytes = await hashKeyBySHA256(key);
  const messageBytes = extractBytesFromBlob(input);
  const [partialOutputs, outputStream] = xorKeyStream(messageBytes, keyBytes, nonce);
  const output = extractBlobFromBytes(outputStream);

  return [partialOutputs, output, resolvedKey];
}

type ChaCha20State = [
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint,
];

/**
 * Adds two 32-bit integers modulo 2^32.
 * @param a left operand
 * @param b right operand
 * @returns the sum of [a] and [b] modulo 2^32.
 */
const sum = (a: bigint, b: bigint): bigint => (a + b) & 0xffffffffn;

/**
 * Cyclically rotates the bits of a 32-bit integer to the left.
 * @param a the data to rotate left.
 * @param b the number of bits to rotate left.
 * @returns the rotated data.
 */
const ROTL = (a: bigint, b: bigint): bigint => (0xffffffffn & (a << b)) | (a >> (32n - b));

type QuarterRound = (state: ChaCha20State, a: number, b: number, c: number, d: number) => void;

/**
 * Applies the ChaCha20 quarter round operation to the state.
 * @param state the ChaCha20 state
 * @param a the first index
 * @param b the second index
 * @param c the third index
 * @param d the fourth index
 */
const quarterRound: QuarterRound = (state, a, b, c, d): void => {
  state[a] = sum(state[a], state[b]), state[d] ^= state[a], state[d] = ROTL(state[d], 16n);
  state[c] = sum(state[c], state[d]), state[b] ^= state[c], state[b] = ROTL(state[b], 12n);
  state[a] = sum(state[a], state[b]), state[d] ^= state[a], state[d] = ROTL(state[d], 8n);
  state[c] = sum(state[c], state[d]), state[b] ^= state[c], state[b] = ROTL(state[b], 7n);
};

/**
 * Adds two ChaCha20 states together element-wise.
 * @param a the left state
 * @param b the right state
 * @returns the sum of the two states.
 */
const addState = (a: ChaCha20State, b: ChaCha20State): ChaCha20State => {
  const output: bigint[] = [];

  for (let i = 0; i < a.length; ++i) {
    output.push(sum(a[i], b[i]));
  }

  return output as ChaCha20State;
};

/**
 * Converts a blob to an array of 32-bit integers.
 * @param value the blob to convert to words
 * @param count the amount of words to return.
 * @returns the blob as an array of 32-bit integers.
 */
const words = (value: bigint, count?: number): bigint[] => {
  const output: bigint[] = [];
  while (value > 0 || (count && output.length < count)) {
    output.unshift(value & 0xFFFFFFFFn);
    value >>= 32n;
  }

  if (count != null)
    while (output.length > count) {
      output.pop();
    }

  return output;
};


/**
 * 
 * @param key 256-bit integer
 * @param nonce 96-bit integer
 * @param count 32-bit block integer
 */
const chaChaBlock = (key: bigint, nonce: bigint, count: bigint):
  [[title: string, content: string][], bigint[]] => {
  const partialOutputs: [title: string, content: string][] = [];
  partialOutputs.push([
    `Block ${count} Generation`,
    ``,
  ]);

  const state = [
    0x61707865n, 0x3320646en, 0x79622d32n, 0x6b206574n,
    ...words(key, 8),
    count, ...words(nonce, 3),
  ] as ChaCha20State;
  const stateCopy: ChaCha20State = [...state];

  for (let i = 0; i < 20; i += 2) {
    // Odd round
    quarterRound(stateCopy, 0, 4, 8, 12); // column 1
    quarterRound(stateCopy, 1, 5, 9, 13); // column 2
    quarterRound(stateCopy, 2, 6, 10, 14); // column 3
    quarterRound(stateCopy, 3, 7, 11, 15); // column 4

    // Even round
    quarterRound(stateCopy, 0, 5, 10, 15); // diagonal 1 (main diagonal)
    quarterRound(stateCopy, 1, 6, 11, 12); // diagonal 2
    quarterRound(stateCopy, 2, 7, 8, 13); // diagonal 3
    quarterRound(stateCopy, 3, 4, 9, 14); // diagonal 4
  }

  const output = addState(state, stateCopy);
  partialOutputs.push([
    `Key Stream ${count}`,
    output//
      .flatMap((p) => extractBytesFromBlob(p).reverse())
      .map((word) => "0x" + word.toString(16).padStart(2, "0"))
      .join(" "),
  ]);

  return [partialOutputs, output];
};

/**
 * Generates an infinite iterable of ChaCha20 key stream bytes.
 *   It is generated JIT.
 * @param key the input key
 * @param nonce the input once value.
 */
const keyStream = function* (key: bigint, nonce: bigint):
  Generator<[[title: string, content: string][], bigint]> {
  for (let i = 1n; ; ++i) {
    const [partialOutput, block] = chaChaBlock(key, nonce, i);

    for (const word of block) {
      for (let byte of words(word, 4)) {
        while (byte > 0) {
          yield [partialOutput, byte & 0xFFn];
          byte >>= 8n;
        }
      }
    }
  }
};

/**
 * XORs the input bytes with the ChaCha20 key stream.
 * @param input the input bytes
 * @param key the input key
 * @param nonce the input nonce
 * @returns the bytes xor'd with the key stream.
 */
const xorKeyStream = (input: bigint[], key: bigint, nonce: bigint):
  [[title: string, content: string][], bigint[]] => {
  const output: bigint[] = [];
  const keyGen = keyStream(key, nonce);
  const partialOutputs: [title: string, content: string][] = [];

  for (const byte of input) {
    const [partialOutput, keyByte] = keyGen.next().value as
      [[title: string, content: string][], bigint];

    if (partialOutputs.length <= 0 || partialOutputs.at(-1) !== partialOutput.at(-1)) {
      partialOutputs.push(...partialOutput);
    }
    output.push(byte ^ keyByte);
  }

  return [partialOutputs, output];
}

/**
 * Extracts bytes from an arbitrary-length integer.
 * @param blob an arbitrary-length integer
 * @returns an array of bytes integers
 */
const extractBytesFromBlob = (blob: bigint): bigint[] => {
  const blocks: bigint[] = [];
  while (blob > 0) {
    blocks.unshift(blob & 0xFFn);
    blob >>= 8n;
  }

  return blocks;
};


/**
 * Combines 128-bit blocks into an arbitrary-length integer.
 * @param blocks array of 128-bit integers
 * @returns an arbitrary-length integer
 */
const extractBlobFromBytes = (blocks: bigint[]): bigint => {
  let hex = 0n;

  for (const block of blocks) {
    hex <<= 8n;
    hex |= block;
  }

  return hex;
};

/**
 * Groups the data into groups consisting of at most [groupSize] elements.
 * @param data the data to be grouped
 * @param groupSize the size of each group
 * @returns an array of groups of the specified size
 */
const groupData = <T>(data: T[], groupSize: number): T[][] => {
  const output: T[][] = [];
  for (let i = 0; i < data.length; i += groupSize) {
    const group: T[] = [];
    for (let j = i; j < data.length && j < i + groupSize; ++j) {
      group.push(data[j]);
    }
    output.push(group);
  }

  return output;
}
