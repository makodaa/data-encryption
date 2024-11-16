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