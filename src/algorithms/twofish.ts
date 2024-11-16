const hex = (n: bigint | number) => typeof n === "bigint" ? n.toString(16) : (n >>> 0).toString(16);

export const encrypt: EncryptDecrypt = (text, key) => {
  /// Key resolution
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  const hashedKey = hash(resolvedKey) & ((1n << 128n) - 1n);

  const keySchedule = generateKeySchedule(hashedKey);
  const blocks = splitStringInto128BitBlocks(text);
  const encryptedBytes = blocks.map((block) => encryptBlock(block, keySchedule));
  const string = extractStringFrom128BitBytes(encryptedBytes.map(s => s[1]));

  return [[], string, resolvedKey];
};

export const decrypt: EncryptDecrypt = (text, key) => {
  /// Key resolution
  const resolvedKey = key == null ? random64BitKey().toString() : key;
  const hashedKey = hash(resolvedKey) & ((1n << 128n) - 1n);

  const keySchedule = generateKeySchedule(hashedKey);
  const blocks = splitStringInto128BitBlocks(text);
  const decryptedBytes = blocks.map((block) => decryptBlock(block, keySchedule));
  const string = extractStringFrom128BitBytes(decryptedBytes.map(s => s[1]));

  return [[], string, resolvedKey];
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

type IrreduciblePolynomial = 0b101101001n | 0b101001101n;

type int32 = bigint;
type KeySchedule = [K: bigint[], S: bigint[]];
type EncryptDecrypt = (
  text: string,
  key?: string
) => //
  [partialOutputs: string[], finalOutput: string, key: string];

const generateKeySchedule = (key: bigint): KeySchedule => {
  /// The key consists of 8k bytes from m[0] to m[8*k - 1].
  ///   The bytes are converted into 2k words of 32 bits each.

  const m: bigint[] = new Array(8 * k).fill(0n);
  for (let i = 0; i < 8 * k; ++i) {
    m[8 * k - 1 - i] = (key >> BigInt(8 * i)) & 0xFFn;
  }

  const M: bigint[] = new Array(2 * k).fill(0n);
  for (let i = 0; i <= 2 * k - 1; ++i) {
    for (let j = 0; j <= 3; ++j) {
      M[i] += m[4 * i + j] * (2n ** BigInt(8 * j));
    }
  }

  const mEven: bigint[] = [];
  const mOdd: bigint[] = [];
  for (let i = 0; i < M.length; i += 2) {
    mEven.push(M[i]);
    mOdd.push(M[i + 1]);
  }

  const s = new Array(k).fill(0).map(_ => new Array(4).fill(0n));
  const vectors = groupData(m, 8);
  for (let i = 0; i < k; ++i) {
    s[i] = rs(vectors[i]);
  }

  const S = new Array<bigint>(k).fill(0n);
  for (let i = 0; i <= k - 1; ++i) {
    S[i] = 0n;
    for (let j = 0; j <= 3; ++j) {
      S[i] += s[i][j] * (2n ** BigInt(8 * j));
    }
  }
  S.reverse();

  const rho = 0x1010101n;
  const keys: bigint[] = [];
  for (let i = 0n; i < 20n; ++i) {
    const A = H(2n * i * rho, mEven);
    const B = ROL(H((2n * i + 1n) * rho, mOdd), 8n);

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
 * @returns The encrypted block of 128-bit data.
 */
const encryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  let data = block;
  const bytes: bigint[] = [];
  while (bytes.length < 16) {
    bytes.unshift(data & 0xFFn);
    data >>= 8n;
  }
  const P = littleEndianConversion(bytes);
  let [r0, r1, r2, r3] = inputWhiten(P, keySchedule);

  /// In each of the 16 rounds, the first two words are used as the input to the function F,
  ///   which also takes the round number as input. The third word is XOR'd with the first output
  ///   of F, and then rotated by left.
  for (let r = 0; r < 16; ++r) {
    const [f0, f1] = F(r0, r1, r, keySchedule);
    [r0, r1, r2, r3] = [ROR(r2 ^ f0, 1n), ROL(r3, 1n) ^ f1, r0, r1];
  }

  [r0, r1, r2, r3] = outputWhiten([r2, r3, r0, r1], keySchedule);
  const outputBytes = inverseLittleEndianConversion([r0, r1, r2, r3]);

  let output = 0n;
  for (let i = 0; i < 16; ++i) {
    output |= outputBytes[15 - i] << BigInt(8 * i);
  }

  return [[], output];
};

/**
 * Decrypts a block of data using the TwoFish algorithm.
 * @param block A block of 128-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The decrypted block of 128-bit data.
 */
const decryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  let data = block;
  const bytes: bigint[] = [];
  while (bytes.length < 16) {
    bytes.unshift(data & 0xFFn);
    data >>= 8n;
  }
  const P = littleEndianConversion(bytes);
  let [r0, r1, r2, r3] = outputWhiten(P, keySchedule);

  /// In each of the 16 rounds, the first two words are used as the input to the function F,
  ///   which also takes the round number as input. The third word is XOR'd with the first output
  ///   of F, and then rotated by left.
  for (let r = 15; r >= 0; --r) {
    const [f0, f1] = F(r0, r1, r, keySchedule);
    [r0, r1, r2, r3] = [ROL(r2, 1n) ^ f0, ROR(r3 ^ f1, 1n), r0, r1];
  }

  [r0, r1, r2, r3] = inputWhiten([r2, r3, r0, r1], keySchedule);
  const outputBytes = inverseLittleEndianConversion([r0, r1, r2, r3]);

  let output = 0n;
  for (let i = 0; i < 16; ++i) {
    output |= outputBytes[15 - i] << BigInt(8 * i);
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

/**
 * Multiplies two elements in GF(2^8) over the irreducible polynomial as given by the user.
 * @param a left operand
 * @param b right operand
 * @param irreduciblePolynomial the irreducible polynomial to use for GF(2^8) multiplication
 * @returns the product of the two operands over G(2)[x]/(irreduciblePolynomial)
 */
const multiplyGF2_8 = (
  a: bigint,
  b: bigint,
  irreduciblePolynomial: IrreduciblePolynomial
): bigint => {
  let product = 0n;
  while (b > 0) {
    if ((b & 1n) != 0n) {
      product ^= a;
    }

    a <<= 1n;
    b >>= 1n;

    if (a & (1n << 8n)) {
      a ^= irreduciblePolynomial;
    }
  }

  return product;
};

const multiplyMatrixToVector = (
  matrix: bigint[][],
  vector: bigint[],
  polynomial: IrreduciblePolynomial,
): bigint[] => {
  if (matrix[0].length != vector.length) {
    throw new Error(`Cannot apply (${matrix.length}, ${matrix[0].length})-` +
      `matrix to ${vector.length}-vector`);
  }

  const output: bigint[] = new Array(matrix.length).fill(0n);
  for (let i = 0; i < matrix.length; ++i) {
    for (let j = 0; j < vector.length; ++j) {
      output[i] ^= multiplyGF2_8(matrix[i][j], vector[j], polynomial);
    }
  }

  return output;
};

const inputWhiten = (blocks: bigint[], [K, S]: KeySchedule): bigint[] => {
  const outputBlocks: bigint[] = [...blocks];
  for (let i = 0; i < 4; ++i) {
    outputBlocks[i] = blocks[i] ^ K[i];
  }

  return blocks;
};

const outputWhiten = (blocks: bigint[], [K, S]: KeySchedule): bigint[] => {
  const outputBlocks: bigint[] = [...blocks];
  for (let i = 0; i < 4; ++i) {
    outputBlocks[i] = blocks[(i + 2) % 4] ^ K[i + 4];
  }

  return blocks;
};

const rs = (block: bigint[]): bigint[] => multiplyMatrixToVector(MATRIX.rs, block, 0b101001101n);
const mds = (block: bigint[]): bigint[] => multiplyMatrixToVector(MATRIX.mds, block, 0b101101001n);

const F = (
  r0: int32,
  r1: int32,
  round: number,
  [K, S]: KeySchedule,
): [int32, int32] => {
  const t0 = H(r0, S);
  const t1 = H(ROL(r1, 8n), S);

  const f0 = (t0 + t1 + K[2 * round + 8]) & 0xFFn;
  const f1 = (t0 + 2n * t1 + K[2 * round + 9]) & 0xFFn;

  return [f0, f1];
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
  for (let j = 0; j < 4; ++j) {
    x[j] = (X >> BigInt(8 * j)) & 0xFFn;

    for (let i = 0; i <= k - 1; ++i) {
      l[i] ??= [];
      l[i][j] = (L[i] >> BigInt(8 * j)) & 0xFFn;
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


const _qSubstitute = (block: bigint, tables: bigint[][]): bigint => {
  const t0 = (x: bigint): bigint => tables[0][Number(x)];
  const t1 = (x: bigint): bigint => tables[1][Number(x)];
  const t2 = (x: bigint): bigint => tables[2][Number(x)];
  const t3 = (x: bigint): bigint => tables[3][Number(x)];

  let [a, b] = [block / 16n, block % 16n];
  [a, b] = [a ^ b, ((a ^ ROR4(b, 1n) ^ 8n * a)) % 16n];
  [a, b] = [t0(a), t1(b)];
  [a, b] = [a ^ b, (a ^ ROR4(b, 1n) ^ (8n * a)) % 16n];
  [a, b] = [t2(a), t3(b)];

  return 16n * b + a;
};
/**
 * Substitutes the data according to the q0 tables.
 * @param x the block of data to permute
 * @returns the permuted block of data
 */
const q0 = (x: bigint): bigint => _qSubstitute(x, Object.values(PERMUTATION.q0));

/**
 * Substitutes the data according to the q1 tables.
 * @param x the block of data to permute
 * @returns the permuted block of data
 */
const q1 = (x: bigint): bigint => _qSubstitute(x, Object.values(PERMUTATION.q1));

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
const extractStringFrom128BitBytes = (blocks: bigint[]): string => {
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