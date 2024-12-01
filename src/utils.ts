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


export type PartialOutputs = [title: string, value: string | null][];
export type EncryptDecrypt = (messageHex: bigint, key?: string, nonce?: bigint) => //
  Promise<[partialOutputs: PartialOutputs, finalOutput: bigint, key: string, keyHash: bigint]>;


/**
 * Groups the data into groups consisting of at most [groupSize] elements.
 * @param data the data to be grouped
 * @param groupSize the size of each group
 * @returns an array of groups of the specified size
 */
export const groupData = <T>(data: T[], groupSize: number): T[][] => {
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

export const byteHex = (byte: bigint): string => byte.toString(16).padStart(2, "0");
export const dwordHex = (dword: bigint): string => dword.toString(16).padStart(8, "0");