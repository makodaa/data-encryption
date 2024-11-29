export const stringToBytes = (str: string): bigint => {
  let output = 0n;
  for (let i = 0; i < str.length; i++) {
    output = output << 8n;
    output += BigInt(str.charCodeAt(i));
  }

  return output;
};

export const bytesToString = (bytes: bigint): string => {
  let output = "";
  while (bytes > 0) {
    output = String.fromCharCode(Number(bytes & 0xFFn)) + output;
    bytes = bytes >> 8n;
  }

  return output;
}

const aggregateBytes = (bytes: Uint8Array): bigint => {
  let output = 0n;
  for (let i = 0; i < bytes.length; ++i) {
    output = (output << 8n) | BigInt(bytes[i]);
  }

  return output;
};

export const hashKeyBySHA256 = async (key: string): Promise<bigint> => {
  const keyBytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));

  return aggregateBytes(new Uint8Array(keyBytes));
};

/**
 * Generates a random 128-bit key.
 * @returns a random 128-bit key.
 */
export const random128BitKey = (): string => {
  return crypto.randomUUID().split("-").join("");
};


export type PartialOutputs = [title: string, value: string][];
export type EncryptDecrypt = (messageHex: bigint, key?: string, nonce?: bigint) => //
  Promise<[partialOutputs: PartialOutputs, finalOutput: bigint, key: string, keyHash: bigint]>;
