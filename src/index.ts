import * as TwoFish from "./algorithms/twofish";

console.log("Hello World!");

const [[], encrypted, key] = TwoFish.encrypt("this is a message.");
const [[], decrypted, _] = TwoFish.decrypt(encrypted, key);
console.log({ encrypted, decrypted });