/**
 * TwoFish algorithm implementation.
 * 
 * The TwoFish algorithm is a symmetric key block cipher with a block size of 128 bits
 *  and key sizes of 128, 192, or 256 bits. It is based on a Feistel network structure
 * and uses a key-dependent S-boxes, a complex key schedule, and a pre-whitening and
 * post-whitening stage.
 * 
 * The documents used as a reference can be seen in the following documents:
 *   Schneier, B., Kelsely, J., Whiting, D., Wagner, D., Hall, C., & Ferguson, N. (1998, June 15). Twofish: a 128-Bit block cipher. Schneier on Security. https://www.schneier.com/wp-content/uploads/2016/02/paper-twofish-paper.pdf
 */

import {
  byteHex,
  dwordHex,
  EncryptDecrypt,
  groupData,
  hashKeyBySHA256,
  PartialOutputs,
  random128BitKey,
} from "../utils";

const BIT_128 = (1n << 128n) - 1n;
const BIT_32 = (1n << 32n) - 1n;

export const encrypt: EncryptDecrypt = async (messageHex, key, _) => {
  const encryptedBlocks: bigint[] = [];
  const partialOutputs: PartialOutputs = [];

  /// Key resolution
  const resolvedKey = key || random128BitKey();
  const hashedKey = await hashKeyBySHA256(resolvedKey) & BIT_128;

  const [schedulePartialOutputs, keySchedule] = generateKeySchedule(hashedKey);
  partialOutputs.push(...schedulePartialOutputs);
  console.log(schedulePartialOutputs);

  const blocks = extract128BitBytesFromBLOB(messageHex);
  const outputs = blocks.map((block) => encryptBlock(block, keySchedule));

  partialOutputs.push(["Encryption Proper", ""]);

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

  const output = extractBLOBFrom128BitBytes(encryptedBlocks);

  return [partialOutputs, output, resolvedKey, hashedKey];
};

export const decrypt: EncryptDecrypt = async (messageHex, key, _) => {
  const decryptedBlocks: bigint[] = [];
  const partialOutputs: PartialOutputs = [];

  /// Key resolution
  const resolvedKey = key || random128BitKey();
  const hashedKey = await hashKeyBySHA256(resolvedKey) & BIT_128;

  const [schedulePartialOutputs, keySchedule] = generateKeySchedule(hashedKey);
  partialOutputs.push(...schedulePartialOutputs);

  const blocks = extract128BitBytesFromBLOB(messageHex);
  const outputs = blocks.map((block) => decryptBlock(block, keySchedule));
  partialOutputs.push(["Decryption Proper", ""]);

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
  const output = extractBLOBFrom128BitBytes(decryptedBlocks);

  return [partialOutputs, output, resolvedKey, hashedKey];
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
const SUBSTITUTION = {
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

/**
 * These are the two irreducible polynomials mentioned
 *   in the TwoFish paper.
 */
type IrreduciblePolynomial = 0b101101001n | 0b101001101n;

/**
 * The key schedule produces two outputs: the subkeys and the S-boxes.
 */
type KeySchedule = [K: bigint[], S: bigint[]];

/**
 * This function generates the subkeys and S-boxes for the TwoFish algorithm.
 *   Three vectors are used in creating the subkeys:
 *      - M[e]: The even DWORD
 *      - M[o]: The odd DWORD
 *      - S: The S-boxes.
 * 
 * @param key The main key to generate the key schedule from
 * @returns the computed key schedule
 */
const generateKeySchedule = (key: bigint): [PartialOutputs, KeySchedule] => {
  /// The key consists of 8k bytes from m[0] to m[8*k - 1].
  ///   The bytes are converted into 2k words of 32 bits each.

  const partialOutputs: PartialOutputs = [];
  partialOutputs.push(["Key Schedule", null]);

  const m: bigint[] = extractBytesFromBlob(key, 16n);
  partialOutputs.push([
    "Separation of Key into bytes",
    m.map(byteHex).join(", "),
  ]);

  const M: bigint[] = new Array(2 * k).fill(0n);
  for (let i = 0; i <= 2 * k - 1; ++i) {
    for (let j = 0; j <= 3; ++j) {
      M[i] += m[4 * i + j] << BigInt(8 * j);
    }
  }
  partialOutputs.push([
    "Conversion of bytes to 32-bit words",
    M.map(dwordHex).join(", "),
  ]);

  const mEven: bigint[] = [];
  const mOdd: bigint[] = [];
  for (let i = 0; i < M.length; i += 2) {
    mEven.push(M[i]);
    mOdd.push(M[i + 1]);
  }
  partialOutputs.push([
    "Separation of 32-bit words into even and odd words",
    "M[even]: " + mEven.map(dwordHex).join(", ") + "\n" +
    "M[odd]: "  +  mOdd.map(dwordHex).join(", "),
  ]);

  const S: bigint[] = [];
  const vectors = groupData(m, 8);
  partialOutputs.push(["Generation of S-box key", null]);
  for (let i = 0; i < k; ++i) {
    const si = rs(vectors[i]);
    partialOutputs.push([
      `Generation of S-box key ${i + 1}`,
      `V[${i}]: ${vectors[i].map(byteHex).join(", ")}` + "\n" +
      `S[${i}] = (RS)(V[${i}]): ${si.map(byteHex).join(", ")}`,
    ]);

    S.unshift(si[0] | (si[1] << 8n) | (si[2] << 16n) | (si[3] << 24n));
  }
  partialOutputs.push([
    "Generation of S-box keys",
    S.map(dwordHex).join(", "),
  ]);

  const rho = 0x1010101n;
  const keys: bigint[] = [];
  for (let i = 0n; i < 20n; ++i) {
    let A = H(2n * i * rho, mEven);
    let B = H((2n * i + 1n) * rho, mOdd);
    B = ROTL(B, 8n);

    let K2i = (A + B) & BIT_32;
    let K2i1 = (A + 2n * B) & BIT_32;
    K2i1 = ROTL(K2i1, 9n);

    partialOutputs.push([
      `Generation of Subkeys K[${i * 2n}] and K[${i * 2n + 1n}]`,
      `A: ${dwordHex(A)}, B: ${dwordHex(B)}` + "\n" +
      `K[${i * 2n}]: ${dwordHex(K2i)}, K[${i * 2n + 1n}]: ${dwordHex(K2i1)}`,
    ]);

    keys.push(K2i);
    keys.push(K2i1);
  }

  partialOutputs.push([
    "Generation of Subkeys",
    keys.map(dwordHex).join(", "),
  ]);

  return [partialOutputs, [keys, S]];
};

type EncryptDecryptBlock = (
  block: bigint,
  keySchedule: KeySchedule,
) => [PartialOutputs, bigint];

/**
 * Encrypts a block of data using the TwoFish algorithm.
 * @param block A block of 128-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The encrypted block of 128-bit data.
 */
const encryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: PartialOutputs = [];

  const bytes = extractBytesFromBlob(block, 16n);
  let [r0, r1, r2, r3] = littleEndianConversion(bytes);
  partialOutputs.push([
    "Input Block",
    `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
  ]);

  [r0, r1, r2, r3] = inputWhiten([r0, r1, r2, r3], keySchedule);
  partialOutputs.push([
    "Input Whitening",
    `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
  ]);

  /// In each of the 16 rounds, the first two words are used as the input to the function F,
  ///   which also takes the round number as input. The third word is XOR'd with the first output
  ///   of F, and then rotated by left.
  for (let r = 0; r < 16; ++r) {
    const [f0, f1] = F(r0, r1, r, keySchedule);
    [r0, r1, r2, r3] = [ROTR(r2 ^ f0, 1n), ROTL(r3, 1n) ^ f1, r0, r1];

    partialOutputs.push([
      `Round ${r + 1}`,
      `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
    ]);
  }

  [r0, r1, r2, r3] = outputWhiten([r2, r3, r0, r1], keySchedule);
  partialOutputs.push([
    "Output Whitening",
    `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
  ]);

  const outputBytes = inverseLittleEndianConversion([r0, r1, r2, r3]);

  let output = 0n;
  for (let i = 0; i < 16; ++i) {
    output |= outputBytes[15 - i] << BigInt(8 * i);
  }

  return [partialOutputs, output];
};

/**
 * Decrypts a block of data using the TwoFish algorithm.
 * @param block A block of 128-bit data.
 * @param keySchedule The key schedule generated.
 * @returns The decrypted block of 128-bit data.
 */
const decryptBlock: EncryptDecryptBlock = (block, keySchedule) => {
  const partialOutputs: PartialOutputs = [];

  const bytes = extractBytesFromBlob(block, 16n);
  let [r0, r1, r2, r3] = littleEndianConversion(bytes);
  partialOutputs.push([
    "Input Block",
    `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
  ]);

  [r0, r1, r2, r3] = outputWhiten([r0, r1, r2, r3], keySchedule);
  partialOutputs.push([
    "Reverse Output Whitening",
    `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`,
  ]);

  /// In each of the 16 rounds, the first two words are used as the input to the function F,
  ///   which also takes the round number as input. The third word is XOR'd with the first output
  ///   of F, and then rotated by left.
  for (let r = 15; r >= 0; --r) {
    const [f0, f1] = F(r0, r1, r, keySchedule);
    [r0, r1, r2, r3] = [ROTL(r2, 1n) ^ f0, ROTR(r3 ^ f1, 1n), r0, r1];

    partialOutputs.push([
      `Round ${16 - r}`,
      `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
    ]);
  }

  [r0, r1, r2, r3] = inputWhiten([r2, r3, r0, r1], keySchedule);
  partialOutputs.push([
    "Reverse Input Whitening",
    `${dwordHex(r0)}, ${dwordHex(r1)}, ${dwordHex(r2)}, ${dwordHex(r3)}`
  ]);

  const outputBytes = inverseLittleEndianConversion([r0, r1, r2, r3]);

  let output = 0n;
  for (let i = 0; i < 16; ++i) {
    output |= outputBytes[15 - i] << BigInt(8 * i);
  }

  return [partialOutputs, output];
};

/**
 * Extracts bytes from a blob of data.
 * @param blob the blob to extract bytes from
 * @param count (optional) the number of bytes to extract
 * @returns an array of bytes extracted from the blob
 */
const extractBytesFromBlob = (blob: bigint, count?: bigint): bigint[] => {
  const bytes: bigint[] = [];
  while (blob > 0 || (count != null && bytes.length < count)) {
    bytes.unshift(blob & 0xFFn);
    blob >>= 8n;
  }

  return bytes;
}

/**
 * Converts a 128-bit block into 32-bit blocks.
 * @param p bytes of information to be converted into 32-bit blocks
 * @returns the 32-bit blocks of the 128-bit block
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

/**
 * Converts a sequence of 32-bit blocks into contiguous bytes.
 * @param C blocks of 32-bit data
 * @returns the contiguous bytes of the 128-bit block
 */
const inverseLittleEndianConversion = (C: bigint[]): bigint[] => {
  const c = new Array(16)//
    .fill(0)
    .map((_, i) => (C[Math.floor(i / 4)] >> BigInt(8 * (i % 4))) & 0xFFn);

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

/**
 * Multiplies the matrix by the vector under GF(2^8) defined
 *   as GF(2)[x]/f(x) where f(x) = irreducible polynomial.
 * @param matrix the matrix to multiply the vector with 
 * @param vector the vector to be multiplied by
 * @param polynomial the irreducible polynomial to use for GF(2^8) multiplication
 * @returns the product of the matrix and the vector
 */
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

/**
 * Whitens the block data according to the key schedule.
 * @param blocks the blocks of data to be output-whitened
 * @param param1 the computed key schedule
 * @returns the whitened blocks of data
 */
const inputWhiten = (blocks: bigint[], [K, S]: KeySchedule): bigint[] => {
  const outputBlocks: bigint[] = [...blocks];
  for (let i = 0; i < 4; ++i) {
    outputBlocks[i] = blocks[i] ^ K[i];
  }

  return outputBlocks;
};

/**
 * Whitens the block data according to the key schedule.
 * @param blocks the blocks of data to be output-whitened
 * @param param1 the computed key schedule
 * @returns the whitened blocks of data
 */
const outputWhiten = (blocks: bigint[], [K, S]: KeySchedule): bigint[] => {
  const outputBlocks: bigint[] = [...blocks];
  for (let i = 0; i < 4; ++i) {
    outputBlocks[i] = blocks[i] ^ K[i + 4];
  }

  return outputBlocks;
};

/**
 * Multiplies the given vector by the Reed-Solomon matrix under GF(2^8)
 *   defined as GF(2)[x]/f(x) where f(x) = x^8 + x^6 + x^3 + x^2 + 1.
 * The vector must be of length 8.
 * @param vector the vector to multiply by the Reed-Solomon matrix
 * @returns the result of multiplying the block by the Reed-Solomon matrix
 */
const rs = (vector: bigint[]): bigint[] =>
  multiplyMatrixToVector(MATRIX.rs, vector, 0b101001101n);

/**
 * Multiplies the given vector by the MDS matrix under GF(2^8)
 *   defined as GF(2)[x]/f(x) where f(x) = x^8 + x^6 + x^5 + x^3 + 1.
 * The vector must be of length 4.
 * @param vector the vector to multiply by the MDS matrix
 * @returns the result of multiplying the block by the MDS matrix
 */
const mds = (vector: bigint[]): bigint[] =>
  multiplyMatrixToVector(MATRIX.mds, vector, 0b101101001n);

/**
 * Key dependent permutation of 64-bit values.
 * @param r0 the first dword
 * @param r1 the second dword
 * @param round the round number
 * @param param3 the key schedule
 * @returns two values, f0 and f1 according to the TwoFish algorithm
 */
const F = (r0: bigint, r1: bigint, round: number, [K, S]: KeySchedule): [bigint, bigint] => {
  const t0 = H(r0, S);
  const t1 = H(ROTL(r1, 8n), S);

  const f0 = (t0 + t1 + K[2 * round + 8]) & 0xFFn;
  const f1 = (t0 + 2n * t1 + K[2 * round + 9]) & 0xFFn;

  return [f0, f1];
};


/**
 * The H function is a 32-bit block cipher that takes a 32-bit block of data
 *  and a 128-bit key schedule and produces a 32-bit block of data.
 * @param X The block of data.
 * @param L The different values of the key schedule.
 * @returns The result of the H function.
 */
const H = (X: bigint, L: bigint[]): bigint => {
  /// [x] and [l] are byte-separations of [X] and [L] respectively.
  const x = bytesOfSingle(X, 4);
  const l = bytesOfGroup(L, 4);

  let y0: bigint, y1: bigint, y2: bigint, y3: bigint;
  [y0, y1, y2, y3] = [x[0]        ,   x[1]      , x[2]        , x[3]];
  [y0, y1, y2, y3] = [q0(y0)      , q1(y1)      , q0(y2)      , q1(y3)];
  [y0, y1, y2, y3] = [y0 ^ l[1][0], y1 ^ l[1][1], y2 ^ l[1][2], y3 ^ l[1][3]];
  [y0, y1, y2, y3] = [q0(y0)      , q0(y1)      , q1(y2)      , q1(y3)];
  [y0, y1, y2, y3] = [y0 ^ l[0][0], y1 ^ l[0][1], y2 ^ l[0][2], y3 ^ l[0][3]];
  [y0, y1, y2, y3] = [q1(y0)      , q0(y1)      , q1(y2)      , q0(y3)];
  const [z0, z1, z2, z3] = mds([y0, y1, y2, y3]);

  return z0 | (z1 << 8n) | (z2 << 16n) | (z3 << 24n);
};

/**
 * Substitutes a block of data according to the given tables.
 *   There must be four tables, each with 16 elements.
 * @param block the block of data to substitute
 * @param tables the tables to substitute the data with
 * @returns the substituted block of data
 */
const _qSubstitute = (block: bigint, tables: bigint[][]): bigint => {
  const t0 = (x: bigint): bigint => tables[0][Number(x)];
  const t1 = (x: bigint): bigint => tables[1][Number(x)];
  const t2 = (x: bigint): bigint => tables[2][Number(x)];
  const t3 = (x: bigint): bigint => tables[3][Number(x)];

  let a: bigint, b: bigint;
  [a, b] = [block / 16n, block % 16n];
  [a, b] = [a ^ b      , (a ^ ROTR4(b, 1n) ^ (8n * a)) % 16n];
  [a, b] = [t0(a)      , t1(b)];
  [a, b] = [a ^ b      , (a ^ ROTR4(b, 1n) ^ (8n * a)) % 16n];
  [a, b] = [t2(a)      , t3(b)];

  return 16n * b + a;
};

/**
 * Substitutes the data according to the q0 tables.
 * @param x the block of data to permute
 * @returns the permuted block of data
 */
const q0 = (x: bigint): bigint => _qSubstitute(x, Object.values(SUBSTITUTION.q0));

/**
 * Substitutes the data according to the q1 tables.
 * @param x the block of data to permute
 * @returns the permuted block of data
 */
const q1 = (x: bigint): bigint => _qSubstitute(x, Object.values(SUBSTITUTION.q1));

/**
 * Extracts 128-bit blocks from an arbitrary-length integer.
 * @param blob an arbitrary-length integer
 * @returns an array of 128-bit integers
 */
const extract128BitBytesFromBLOB = (blob: bigint): bigint[] => {
  const blocks: bigint[] = [];
  while (blob > 0) {
    blocks.unshift(blob & BIT_128);
    blob >>= 128n;
  }

  return blocks;
};

/**
 * Combines 128-bit blocks into an arbitrary-length integer.
 * @param blocks array of 128-bit integers
 * @returns an arbitrary-length integer
 */
const extractBLOBFrom128BitBytes = (blocks: bigint[]): bigint => {
  let hex = 0n;

  for (const block of blocks) {
    hex <<= 128n;
    hex |= block;
  }

  return hex;
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
const ROTL = (block: bigint, shiftAmount: bigint) => cyclicallyLeftShift(block, 32n, shiftAmount);

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
const ROTR = (block: bigint, shiftAmount: bigint) => cyclicallyRightShift(block, 32n, shiftAmount);

/**
 * This cyclically shifts a 4-bit block to the right by the specified amount.
 * @param block the block to shift
 * @param shiftAmount the shift amount
 * @returns the block shifted cyclically to the right by the specified amount
 */
const ROTR4 = (block: bigint, shiftAmount: bigint) => cyclicallyRightShift(block, 4n, shiftAmount);

const bytesOfSingle = (block: bigint, count: number): bigint[] => {
  const bytes: bigint[] = [];

  while (block > 0 || bytes.length < count) {
    bytes.push(block & 0xFFn);
    block >>= 8n;
  }

  return bytes;
}

const bytesOfGroup = (blocks: bigint[], count: number): bigint[][] => {
  const bytes: bigint[][] = [];
  for (const block of blocks) {
    bytes.push(bytesOfSingle(block, count));
  }

  return bytes;
};