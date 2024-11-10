const BLOCK_DIVISION:number = 4;
const ROUNDS:number = 16;
const RS_MATRIX: bigint[][] = [
    [BigInt(0x01), BigInt(0xA4), BigInt(0x55), BigInt(0x87), BigInt(0x5A), BigInt(0x58), BigInt(0xDB), BigInt(0x9E)],
    [BigInt(0xA4), BigInt(0x56), BigInt(0x82), BigInt(0xF3), BigInt(0x1E), BigInt(0xC6), BigInt(0x68), BigInt(0xE5)],
    [BigInt(0x02), BigInt(0xA1), BigInt(0xFC), BigInt(0xC1), BigInt(0x47), BigInt(0xAE), BigInt(0x3D), BigInt(0x19)],
    [BigInt(0xA4), BigInt(0x55), BigInt(0x87), BigInt(0x5A), BigInt(0x58), BigInt(0xDB), BigInt(0x9E), BigInt(0x03)]
];


/**
 * Taken from DES.ts
 * Extracts the bits of a block of data into blocks of data of the specified size.
 * Since the block of data is in a numeric format, the output[0] is automatically zero-padded.
 * @param block a block of data.
 * @param blockSize the size of each block.
 * @returns a list of the blocks of data.
 */
const extractBitsIntoSubBlocks = (block: bigint, blockSize: number): bigint[] => {
    const shiftAmount = BigInt(blockSize);
    const subBlocks: bigint[] = [];
    while (block > 0) {
        subBlocks.unshift(block & ((1n << shiftAmount) - 1n));
        block >>= shiftAmount;
    }

    return subBlocks;
};

/**
 * Taken from DES.ts
 * Takes a string and partitions it into n-bit blocks of data.
 * @param text input string
 * @returns a sequence of n-bit blocks of data.
 */
const splitIntoBlocks = (text: string, key: string): bigint[][] => {
    let bits = 0n;
    for (let i = 0; i < text.length; i++) {
        bits <<= 8n;
        bits += BigInt(text.charCodeAt(i));
    }

    return groupSubBlocksIntoBlocks(extractBitsIntoSubBlocks(bits, 32));
};

const groupSubBlocksIntoBlocks = (subBlocks: bigint[]) => {
    const blocks: bigint[][]  = [];
    for (let i = 0; i < subBlocks.length; i+=4) {
        const block:bigint[] = []
        for (let j = 0; j < BLOCK_DIVISION; j++) {
            const value = subBlocks[i+j] === undefined ? BigInt(0) : subBlocks[i+j];
            block.unshift(value);
        }
        blocks.unshift(block);
    }
    return blocks;
}

function multiplyMatrices(m1:bigint[][], m2:bigint[][]):bigint[][] {
    var result:bigint[][] = [];
    for (var i = 0; i < m1.length; i++) {
        result[i] = [];
        for (var j = 0; j < m2[0].length; j++) {
            var sum = BigInt(0);
            for (var k = 0; k < m1[0].length; k++) {
                sum += m1[i][k] * m2[k][j];
            }
            result[i][j] = sum;
        }
    }
    return result;
}

const whitenInput = (block: bigint[], key: bigint[]) => {
    const whitenedBlock: bigint[] = [];
    for (let i = 0; i < BLOCK_DIVISION; i++) {
        whitenedBlock[i] = block[i] ^ key[i];
    }
    return whitenedBlock;
}

function concatenate32Bits(inputs: bigint[]): bigint {
    let result = 0n;

    for (let i = 0; i < inputs.length; i++) {
        // Shift the current result left by 32 bits to make space for the next input
        result = (result << 32n) | (inputs[i] & 0xFFFFFFFFn);
    }

    return result;
}

// returns [expandedKey:bigint, subkeys:bigint[]]
const createKeySchedule = (key: bigint[]) => {
    const blocksKey: bigint = concatenate32Bits(key.reverse());
    const mKeyArray: bigint[] = extractBitsIntoSubBlocks(blocksKey,8).reverse();
    const mKeyMatrix: bigint[][] = [];
    mKeyArray.forEach((mKey)=>mKeyMatrix.push([mKey]));

    const s = multiplyMatrices(RS_MATRIX, mKeyMatrix);
    const subkeys: bigint[] = [];
    for (let i = 0; i <= 3; i++) {
        let sum: bigint = BigInt(0);
        for (let j = 0; j <= 3; j++) {
            sum += s[j][0] * BigInt(2**(8*j));
        }
    }

    // console.log(subkeys);

}
const feistelRound = (block:{[key: string]: bigint }, key: {[key: string]: bigint }) => {

}

const encrypt = (plaintext: string, key: string) => {
    const blocksPlaintext: bigint[][]  = splitIntoBlocks(plaintext, "P");
    const blocksKey: bigint[] = splitIntoBlocks(key, "K")[0];

    createKeySchedule(blocksKey);

    const blocks_encrypted = [];
    blocksPlaintext.forEach((block)=>{
        const whitened_block = whitenInput(block, blocksKey);
        for (let i = 0; i < ROUNDS; i++) {

        }
    });





};


encrypt("I believe this message should be long enough?", "zzis should also be long enough");

// Whiten input -done
// KeySchedule
// First two fiestel rounds
// Remaining fiestel rounds
//