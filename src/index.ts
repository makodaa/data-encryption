import * as IDEA from "./algorithms/idea";
import * as TwoFish from "./algorithms/twofish";
import { bytesToString, stringToBytes } from "./utils";

console.log("Hello World!");

// const bytes = stringToBytes(
//   "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam. Maecenas ligula massa, varius a, semper congue, euismod non, mi."
// );
// {
//   const [[], encrypted, key] = TwoFish.encrypt(bytes);
//   const [[], decrypted, _] = TwoFish.decrypt(encrypted, key);
//   const decryptedString = bytesToString(decrypted);
//   console.log({ message: bytes, encrypted, decrypted, message2: decryptedString });
// }

// {
//   const [[], encrypted, key] = IDEA.encrypt(bytes);
//   const [[], decrypted, _] = IDEA.decrypt(encrypted, key);
//   const decryptedString = bytesToString(decrypted);
//   console.log({ message: bytes, encrypted, decrypted, message2: decryptedString });
// }

const form = document.getElementsByTagName("form")[0];
const runAlgorithmButton = document.getElementById("run-algorithm");
const processHolder = document.getElementById("process-holder");

const inputResult = document.getElementById("output-input-string");
const keyResult = document.getElementById("output-key-result");
const outputResult = document.getElementById("output-output-result");

const inputType = document.getElementById("input-type");
const outputType = document.getElementById("output-type");

runAlgorithmButton.addEventListener("click", () => {
  console.log("Hi");
  console.log(form.inputString);

  const inputString = form.inputString.value;
  const type = form.selectProcess.value;
  const encryptionType = form.selectEncryption.value as string;
  const key = form.inputKey.value;

  if (encryptionType != "twofish" && encryptionType != "idea") {
    return;
  }

  const encryptionFunctions = { twofish: TwoFish.encrypt, idea: IDEA.encrypt };
  const decryptionFunctions = { twofish: TwoFish.decrypt, idea: IDEA.decrypt };

  switch (type) {
    case "encrypt": {
      /// Since we want to encrypt, we need to do the following steps:
      ///  1. Convert the input string to bytes.
      ///  2. Encrypt the bytes using the TwoFish algorithm.
      ///  3. Convert the encrypted bytes to a hex string.
      ///  4. Display the hex string and the partial outputs.
      const encryptionFunction = encryptionFunctions[encryptionType] as typeof TwoFish.encrypt;

      const bytes = stringToBytes(inputString);
      const [partialOutputs, encrypted, resolvedKey] = encryptionFunction(bytes, key);

      processHolder.innerHTML = "";
      for (let i = 0; i < partialOutputs.length; ++i) {
        const partialOutput = partialOutputs[i];
        const processDiv = document.createElement("div");
        processDiv.classList.add("d-flex", "flex-column", "p-2", "mb-3", "border");
        const processSpan = document.createElement("span");
        processSpan.classList.add("p");
        processSpan.textContent = `Process ${i}: ${partialOutput.map(s => s.map(v => `0x${v.toString(16)}`).join(", ")).join("\t")}`;

        processDiv.appendChild(processSpan);
        processHolder.appendChild(processDiv);
      }

      // Display the input, key, and output.

      inputResult.textContent = inputString;
      keyResult.textContent = resolvedKey;
      outputResult.textContent = encrypted.toString(16);

      inputType.textContent = `(Plaintext)`;
      outputType.textContent = `(Hexadecimal)`

      break;
    }
    case "decrypt": {
      /// Since we want to encrypt, we need to do the following steps:
      ///  1. Convert the input string to bytes.
      ///  2. Encrypt the bytes using the TwoFish algorithm.
      ///  3. Convert the encrypted bytes to a hex string.
      ///  4. Display the hex string and the partial outputs.
      const decryptionFunction = decryptionFunctions[encryptionType] as typeof IDEA.encrypt;

      const bytes = BigInt(`0x${inputString}`);
      const [partialOutputs, encrypted, resolvedKey] = decryptionFunction(bytes, key);

      processHolder.innerHTML = "";
      for (let i = 0; i < partialOutputs.length; ++i) {
        const partialOutput = partialOutputs[i];
        const processDiv = document.createElement("div");
        processDiv.classList.add("d-flex", "flex-column", "p-2", "mb-3", "border");
        const processSpan = document.createElement("span");
        processSpan.classList.add("p");
        processSpan.textContent = `Process ${i}: ${partialOutput.map(s => s.map(v => `0x${v.toString(16)}`).join(", ")).join("\t")}`;

        processDiv.appendChild(processSpan);
        processHolder.appendChild(processDiv);
      }

      // Display the input, key, and output.

      inputResult.textContent = inputString;
      keyResult.textContent = resolvedKey;
      outputResult.textContent = bytesToString(encrypted);

      inputType.textContent = `(Hexadecimal)`;
      outputType.textContent = `(Plaintext)`

      break;
    }
  }

  console.log(type);
});
