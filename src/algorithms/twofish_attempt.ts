export const encrypt: EncryptDecrypt = (text, key) => {
  /// Key resolution
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  // const hashedKey = hash(resolvedKey) & ((1n << 128n) - 1n);
  const hashedKey = 0x00000000000000000000000000000000n;
  
  const keySchedule = generateKeySchedule(hashedKey);
  console.log(keySchedule[0].map(s => s.toString(16)));

  const blocks = splitStringInto128BitBlocks(text);
  const encryptedBytes = blocks.map((block) => encryptBlock(block, keySchedule));

  return [[], encryptedBytes.map(s => s[1].toString(16)).join(""), resolvedKey];
};

const k = 2; // 128 / 64
const MATRIX = {
  mds: [
    [0x01n, 0xEFn, 0x5Bn, 0x5Bn],
    [0x5Bn, 0xEFn, 0xEFn, 0x01n],
    [0xEFn, 0x5Bn, 0x01n, 0xEFn],
    [0xEFn, 0x01n, 0xEFn, 0x5Bn],
  ],
  rs: [
    [0x01n, 0xA4n, 0x55n, 0x87n, 0x5An, 0x58n, 0xDBn, 0x9En],
    [0xA4n, 0x56n, 0x82n, 0xF3n, 0x1En, 0xC6n, 0x68n, 0xE5n],
    [0x02n, 0xA1n, 0xFCn, 0xC1n, 0x47n, 0xAEn, 0x3Dn, 0x19n],
    [0xA4n, 0x55n, 0x87n, 0x5An, 0x58n, 0xDBn, 0x9En, 0x03n],
  ],
};
const PERMUTATION = {
  q0: {
    t0: [0x8n, 0x1n, 0x7n, 0xDn, 0x6n, 0xFn, 0x3n, 0x2n,
      0x0n, 0xBn, 0x5n, 0x9n, 0xEn, 0xCn, 0xAn, 0x4n],
    t1: [0xEn, 0xCn, 0xBn, 0x8n, 0x1n, 0x2n, 0x3n, 0x5n,
      0xFn, 0x4n, 0xAn, 0x6n, 0x7n, 0x0n, 0x9n, 0xDn],
    t2: [0xBn, 0xAn, 0x5n, 0xEn, 0x6n, 0xDn, 0x9n, 0x0n,
      0xCn, 0x8n, 0xFn, 0x3n, 0x2n, 0x4n, 0x7n, 0x1n],
    t3: [0xDn, 0x7n, 0xFn, 0x4n, 0x1n, 0x2n, 0x6n, 0xEn,
      0x9n, 0xBn, 0x3n, 0x0n, 0x8n, 0x5n, 0xCn, 0xAn],
  },
  q1: {
    t0: [0x2n, 0x8n, 0xBn, 0xDn, 0xFn, 0x7n, 0x6n, 0xEn,
      0x3n, 0x1n, 0x9n, 0x4n, 0x0n, 0xAn, 0xCn, 0x5n],
    t1: [0x1n, 0xEn, 0x2n, 0xBn, 0x4n, 0xCn, 0x3n, 0x7n,
      0x6n, 0xDn, 0xAn, 0x5n, 0xFn, 0x9n, 0x0n, 0x8n],
    t2: [0x4n, 0xCn, 0x7n, 0x5n, 0x1n, 0x6n, 0x9n, 0xAn,
      0x0n, 0xEn, 0xDn, 0x8n, 0x2n, 0xBn, 0x3n, 0xFn],
    t3: [0xBn, 0x9n, 0x5n, 0x1n, 0xCn, 0x3n, 0xDn, 0xEn,
      0x6n, 0x4n, 0x7n, 0xFn, 0x2n, 0x0n, 0x8n, 0xAn],
  },
};


type int32 = bigint;
type KeySchedule = [subKeys: bigint[], S: bigint[]];
type EncryptDecrypt = (
  text: string,
  key?: string
) => //
  [partialOutputs: string[], finalOutput: string, key: string];

const generateKeySchedule = (key: bigint): KeySchedule => {
  /// The key consists of 8k bytes from m[0] to m[8*k - 1].
  ///   The bytes are converted into 2k words of 32 bits each.

  const m: bigint[] = new Array(8 * k).fill(0n);
  for (let i = 0; i <= 8 * k; ++i) {
    m[i] = (key >> BigInt(8 * i)) & 0xFFn;
  }

  const M: bigint[] = new Array(2 * k).fill(0n);
  for (let i = 0; i <= 2 * k - 1; ++i) {
    for (let j = 0; j <= 3; ++j) {
      M[i] += m[4 * i + j] * (2n ** BigInt(8 * j));
    }
  }

  const mEven: bigint[] = [];
  const mOdd: bigint[] = [];
  for (let i = 0; i < M.length; ++i) {
    if (i % 2 == 0) {
      mEven.push(M[i]);
    } else {
      mOdd.push(M[i]);
    }
  }

  const s = new Array(k).fill(0).map(_ => new Array<bigint>(4).fill(0n));
  const groupsOfBytes = groupData(m, 8);
  for (let i = 0; i <= k - 1; ++i) {
    s[i] = rs(groupsOfBytes[i]);
  }

  const S = new Array<bigint>(k).fill(0n);
  for (let i = 0; i <= k - 1; ++i) {
    S[i] = 0n;
    for (let j = 0; j <= 3; ++j) {
      S[i] += s[i][j] * (2n ** BigInt(8 * j));
    }
  }
  S.reverse();

  /// From here, the vectors [mEven, mOdd, S] are used for the key schedule.

  const rho = 0x1010101n;
  const keys = [];
  for (let i = 0; i < 20; ++i) {
    const A = H((2n * BigInt(i) * rho) & ((1n << 32n) - 1n), mEven);
    const B = ROL(H(((2n * BigInt(i)) * rho) & ((1n << 32n) - 1n), mOdd), 8n);
    const K2i = (A + B) & ((1n << 32n) - 1n);
    const K2i1 = ROL(A + 2n * B, 9n);

    keys.push(K2i);
    keys.push(K2i1);
  }

  return [keys, S];
};

type EncryptDecryptBlock = (
  block: bigint,
  keySchedule: KeySchedule,
) => [[bigint, bigint][], bigint];

/**
 * Encrypts a block of data using the TwoFish algorithm.
 * @param block A block of 128-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of data.
 */
const encryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  let data = block;
  const bytes: bigint[] = [];
  while (bytes.length < 16) {
    bytes.unshift(data & 0xFFn);
    data >>= 0x8n;
  }
  console.log(bytes.map(s => s.toString(2).padStart(8, "0")));
  console.log(littleEndianConversion(bytes).map(s => s.toString(2).padStart(32, "0")));

  const P = littleEndianConversion(bytes);
  let [r0, r1, r2, r3] = inputWhiten(P, keySchedule);

  /// In each of the 16 rounds, the first two words are used as the input to the function F,
  ///   which also takes the round number as input. The third word is XOR'd with the first output
  ///   of F, and then rotated by left.
  for (let r = 0; r < 16; ++r) {
    const [f0, f1] = F(r0, r1, r, keySchedule);
    [r0, r1, r2, r3] = [ROR(r2 ^ f0, 1n), ROL(r3, 1n) ^ f1, r0, r1];
  }

  [r0, r1, r2, r3] = outputWhiten([r0, r1, r2, r3], keySchedule);
  const outputBytes = inverseLittleEndianConversion([r0, r1, r2, r3]);

  let output = 0n;
  for (let i = 0; i <= 15; ++i) {
    output |= outputBytes[i] << BigInt(8 * i);
  }

  return [[], output];
};

/**
 * 
 * @param p bytes of information to be converted into 
 */
const littleEndianConversion = (p: bigint[]): bigint[] => {
  const P = new Array(4)//
    .fill(0n)//
    .map((_, i) => p[4 * i] | //
      (p[4 * i + 1] << 8n) | //
      (p[4 * i + 2] << 16n) | //
      (p[4 * i + 3] << 24n));

  return P;
};

const inverseLittleEndianConversion = (C: bigint[]): bigint[] => {
  const c = new Array(16)//
    .fill(0)
    .map((_, i) => (C[~~(i / 4)] >> BigInt(8 * (i % 4))) & 0xFFn);

  return c;
}

const multiplyMatrixToVector = (matrix: bigint[][], vector: bigint[]): bigint[] => {
  if (matrix[0].length != vector.length) {
    throw new Error(`Cannot apply (${matrix.length}, ${matrix[0].length})-` +
      `matrix to ${vector.length}-vector`);
  }

  const output: bigint[] = new Array(matrix.length).fill(0n);
  for (let i = 0; i < matrix.length; ++i) {
    for (let j = 0; j < matrix[i].length; ++j) {
      output[i] += matrix[i][j] * vector[j];
    }
  }

  for (let i = 0; i < output.length; ++i) {
    output[i] &= ((1n << 32n) - 1n);
  }

  return output;
};

const inputWhiten = (blocks: bigint[], [subKeys, S]: KeySchedule): bigint[] => {
  const outputBlocks: bigint[] = [...blocks];
  for (let i = 0; i < 4; ++i) {
    outputBlocks[i] = blocks[i] ^ subKeys[i];
  }

  return blocks;
};

const outputWhiten = (blocks: bigint[], [subKeys, S]: KeySchedule): bigint[] => {
  const outputBlocks: bigint[] = [...blocks];
  for (let i = 0; i < 4; ++i) {
    outputBlocks[i] = blocks[(i + 2) % 4] ^ subKeys[i + 4];
  }

  return blocks;
};

const rs = (block: bigint[]): bigint[] => multiplyMatrixToVector(MATRIX.rs, block);
const mds = (block: bigint[]): bigint[] => multiplyMatrixToVector(MATRIX.mds, block);

const F = (
  r0: int32,
  r1: int32,
  round: number,
  [subKeys, S]: KeySchedule,
): [int32, int32] => {
  const t0 = G(r0, [subKeys, S]);
  const t1 = G(ROL(r1, 8n), [subKeys, S]);

  const f0 = (t0 + t1 + subKeys[2 * round + 8]) & ((1n << 32n) - 1n);
  const f1 = (t0 + 2n * t1 + subKeys[2 * round + 9]) & ((1n << 32n) - 1n);

  return [f0, f1];
};

/**
 * 
 * @param X a 32-bit word
 * @param param1 the key schedule
 * @returns 
 */
const G = (X: int32, [subKeys, S]: KeySchedule): bigint => {
  assert(0n <= X && X <= 2n ** 32n - 1n, "Word must be a 32-bit number");

  /// [x] and [l] are byte-separations of [X] and [L] respectively.
  const x: bigint[] = [];
  const l: bigint[][] = [];
  for (let j = 0; j <= 3; ++j) {
    x[j] = (X >> BigInt(8 * j)) & ((1n << 8n) - 1n);
  }

  let [y0, y1, y2, y3] = [x[0], x[1], x[2], x[3]];
  [y0, y1, y2, y3] = [q0(y0), q1(y1), q0(y2), q1(y3)];
  [y0, y1, y2, y3] = [y0 ^ S[0], y1 ^ S[0], y2 ^ S[0], y3 ^ S[0]];
  [y0, y1, y2, y3] = [q0(y0), q0(y1), q1(y2), q1(y3)];
  [y0, y1, y2, y3] = [y0 ^ S[1], y1 ^ S[1], y2 ^ S[1], y3 ^ S[1]];
  [y0, y1, y2, y3] = [q1(y0), q0(y1), q1(y2), q0(y3)];
  const [z0, z1, z2, z3] = mds([y0, y1, y2, y3]);

  return z0 | (z1 << 8n) | (z2 << 16n) | (z3 << 24n);
};

/**
 * 
 * @param X The block of data.
 * @param L The different values of the key schedule.
 * @returns 
 */
const H = (X: int32, L: int32[]): int32 => {
  assert(0n <= X && X <= 2n ** 32n - 1n, "Word must be a 32-bit number");
  L.every((s) => assert(0n <= s && s <= 2n ** 32n - 1n, "Word must be a 32-bit number"));
  assert(L.length == k, "The amount of values in [l] must be equal to [k]");

  /// [x] and [l] are byte-separations of [X] and [L] respectively.
  const x: bigint[] = [];
  const l: bigint[][] = [];
  for (let j = 0; j <= 3; ++j) {
    x[j] = (X >> BigInt(8 * j)) & ((1n << 8n) - 1n);
    for (let i = 0; i <= k - 1; ++i) {
      l[i] ??= [];
      l[i][j] = (L[i] >> BigInt(8 * j)) & ((1n << 8n) - 1n);
    }
  }

  let [y0, y1, y2, y3] = [x[0], x[1], x[2], x[3]];
  [y0, y1, y2, y3] = [q0(y0), q1(y1), q0(y2), q1(y3)];
  [y0, y1, y2, y3] = [y0 ^ l[1][0], y1 ^ l[1][1], y2 ^ l[1][2], y3 ^ l[1][3]];
  [y0, y1, y2, y3] = [q0(y0), q0(y1), q1(y2), q1(y3)];
  [y0, y1, y2, y3] = [y0 ^ l[0][0], y1 ^ l[0][1], y2 ^ l[0][2], y3 ^ l[0][3]];
  [y0, y1, y2, y3] = [q1(y0), q0(y1), q1(y2), q0(y3)];
  const [z0, z1, z2, z3] = mds([y0, y1, y2, y3]);

  return z0 | (z1 << 8n) | (z2 << 16n) | (z3 << 24n);
};

/**
 * Permutes the block of data as specified in the table. The table must be 1-indexed.
 * Values in the table need not to be unique.
 * @param block block of data to permute.
 * @param table an array of indices to permute the block of data with.
 * @returns the permuted block of data.
 */
const permute = (block: bigint, table: bigint[]): bigint => {
  let permuted = 0n;
  for (let i = 0; i < table.length; i++) {
    permuted <<= 1n;
    permuted |= (block >> (table[i] - 1n)) & 1n;
  }

  return permuted;
};


const _qPermute = (block: bigint, tables: bigint[][]): bigint => {
  const t0 = (x: bigint): bigint => permute(x, tables[0]);
  const t1 = (x: bigint): bigint => permute(x, tables[1]);
  const t2 = (x: bigint): bigint => permute(x, tables[2]);
  const t3 = (x: bigint): bigint => permute(x, tables[3]);

  let [a, b] = [block / 16n, block % 16n];
  [a, b] = [a ^ b, ((a ^ ROR4(b, 1n) ^ 8n * a)) % 16n];
  [a, b] = [t0(a), t1(b)];
  [a, b] = [a ^ b, (a ^ ROR4(b, 1n) ^ (8n * a)) % 16n];
  [a, b] = [t2(a), t3(b)];

  return 16n * b + a;
};
/**
 * Permutes the data according to the q0 tables.
 * @param x the block of data to permute
 * @returns the permuted block of data
 */
const q0 = (x: bigint): bigint => _qPermute(x, Object.values(PERMUTATION.q0));

/**
 * Permutes the data according to the q1 tables.
 * @param x the block of data to permute
 * @returns the permuted block of data
 */
const q1 = (x: bigint): bigint => _qPermute(x, Object.values(PERMUTATION.q1));

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

/**
 * Takes a string and partitions it into 128-bit blocks of data.
 * @param text input string
 * @returns a sequence of 128-bit blocks of data.
 */
const splitStringInto128BitBlocks = (text: string): bigint[] => {
  let bits = 0n;
  for (let i = 0; i < text.length; i++) {
    bits <<= 8n;
    bits += BigInt(text.charCodeAt(i));
  }

  const blocks: bigint[] = [];
  while (bits > 0) {
    blocks.unshift(bits & ((1n << 128n) - 1n));
    bits >>= 128n;
  }

  return blocks;
};

/**
 * This function concatenates the 128-bit blocks of data into a string.
 * @param blocks a sequence of 128-bit blocks of data.
 * @returns output string.
 */
const extractStringFromBitBlocks = (blocks: bigint[]): string => {
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
 * Cyclically shifts a block to the left by the specified amount.
 *  Specifically, it shifts the block to the left by the specified amount
 *  and wraps around the block.
 * @param block the block to shift
 * @param blockSize the size of the block
 * @param shiftAmount the amount to shift the block
 * @returns the block shifted cyclically to the left by the specified amount
 */
const cyclicallyLeftShift = (block: bigint, blockSize: bigint, shiftAmount: bigint) =>
  ((block << shiftAmount) | (block >> (blockSize - shiftAmount))) & ((1n << blockSize) - 1n);

/**
 * This cyclically shifts a 32-bit block to the left by the specified amount.
 * @param block the block to shift
 * @param shiftAmount the shift amount
 * @returns the block shifted cyclically to the left by the specified amount
 */
const ROL = (block: bigint, shiftAmount: bigint) => cyclicallyLeftShift(block, 32n, shiftAmount);

/**
 * Cyclically shifts a block to the right by the specified amount.
 *  Specifically, it shifts the block to the right by the specified amount
 *  and wraps around the block.
 * @param block the block to shift
 * @param blockSize the size of the block
 * @param shiftAmount the amount to shift the block
 * @returns the block shifted cyclically to the right by the specified amount
 */
const cyclicallyRightShift = (block: bigint, blockSize: bigint, shiftAmount: bigint) =>
  ((block >> shiftAmount) | ((block & ((1n << shiftAmount) - 1n)) << (blockSize - shiftAmount))) &
  ((1n << blockSize) - 1n);

/**
 * This cyclically shifts a 32-bit block to the right by the specified amount.
 * @param block the block to shift
 * @param shiftAmount the shift amount
 * @returns the block shifted cyclically to the right by the specified amount
 */
const ROR = (block: bigint, shiftAmount: bigint) => cyclicallyRightShift(block, 32n, shiftAmount);

/**
 * This cyclically shifts a 4-bit block to the right by the specified amount.
 * @param block the block to shift
 * @param shiftAmount the shift amount
 * @returns the block shifted cyclically to the right by the specified amount
 */
const ROR4 = (block: bigint, shiftAmount: bigint) => cyclicallyRightShift(block, 4n, shiftAmount);

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

const assert = (condition: boolean, message?: string) => {
  if (!condition) {
    throw new Error(message);
  }
};

const unimplemented = (): never => {
  throw new Error("Unimplemented!");
}