import * as ChaCha20 from "./algorithms/chacha20";
import * as IDEA from "./algorithms/idea";
import * as TwoFish from "./algorithms/twofish";
import { bytesToString, EncryptDecrypt, stringToBytes } from "./utils";

const clearFields = () => {
  form.inputString.value = "";
  form.fileInput.value = null;
  form.inputNonce.value = "";
};

const form = document.getElementsByTagName("form")[0];
const runAlgorithmButton = document.getElementById("run-algorithm");
const processHolder = document.getElementById("process-holder");

const inputResult = document.getElementById("output-input-string");
const keyResult = document.getElementById("output-key-result");
const keyHashResult = document.getElementById("output-key-hash-result");
const outputResult = document.getElementById("output-output-result");

const inputType = document.getElementById("input-type");
const outputType = document.getElementById("output-type");
const fileInput = document.getElementById("fileInput");
const downloadText = document.getElementById("download-text");

form.selectProcess.addEventListener("change", () => {
  clearFields();
});

form.selectEncryption.addEventListener("change", () => {
  clearFields();
  if (form.selectEncryption.value.trim() == "chacha20") {
    document.getElementById("nonce-group").classList.remove("hidden");
  } else {
    document.getElementById("nonce-group").classList.add("hidden");
  }
});

fileInput.addEventListener("change", (e: Event) => {
  const file = (e.target as HTMLInputElement).files[0];
  const type = form.selectProcess.value;

  if (file && file.type === "text/plain" && type === "encrypt") {
    const reader = new FileReader();

    reader.onload = function (e) {
      const content = e.target.result;
      (document.getElementById("inputString") as HTMLInputElement).value =
        content as string;
    };

    reader.readAsText(file);
  } else if (file && file.type === "text/plain" && type === "decrypt") {
    const reader = new FileReader();

    reader.onload = function (e) {
      const content = e.target.result;
      const bytes = [...new Uint8Array(content as ArrayBuffer)];
      const aggregate = bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");

      (document.getElementById("inputString") as HTMLInputElement).value =
        aggregate as string;
    };

    reader.readAsArrayBuffer(file);
  } else {
    alert("Please upload a valid text file.");
  }
});

downloadText.addEventListener("click", () => {
  const type = form.selectProcess.value;

  if (type === "decrypt") {
    const blob = new Blob([outputResult.textContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = "output.txt";

    link.click();
    URL.revokeObjectURL(url);
  } else {
    // I want a pure blob.

    const bytes = [];
    let aggregate = BigInt(`0x${outputResult.textContent}`);
    while (aggregate > 0) {
      bytes.unshift(Number(aggregate & 0xffn));
      aggregate >>= 8n;
    }
    const array = Uint8Array.from(bytes);
    const blob = new Blob([array]);
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = "output.txt";

    link.click();
    URL.revokeObjectURL(url);
  }
});

runAlgorithmButton.addEventListener("click", async () => {
  const inputString = form.inputString.value;
  const type = form.selectProcess.value;
  const encryptionType = form.selectEncryption.value as string;
  const key = form.inputKey.value;
  const nonce = parseInt(form.inputNonce.value || NaN);
  if (Number.isNaN(nonce) && encryptionType == "chacha20") {
    alert("Please enter a valid nonce.");
    return;
  }

  if (encryptionType != "twofish" && encryptionType != "idea" && encryptionType != "chacha20") {
    return;
  }

  const encryptionFunctions = {
    twofish: TwoFish.encrypt,
    idea: IDEA.encrypt,
    chacha20: ChaCha20.encrypt,
  };
  const decryptionFunctions = {
    twofish: TwoFish.decrypt,
    idea: IDEA.decrypt,
    chacha20: ChaCha20.decrypt,
  };

  switch (type) {
    case "encrypt": {
      /// Since we want to encrypt, we need to do the following steps:
      ///  1. Convert the input string to bytes.
      ///  2. Encrypt the bytes using the chosen algorithm.
      ///  3. Convert the encrypted bytes to a hex string.
      ///  4. Display the hex string and the partial outputs.
      const encryptionFunction = encryptionFunctions[encryptionType] as EncryptDecrypt;

      const bytes = stringToBytes(inputString);
      const [partialOutputs, encrypted, resolvedKey, keyHash] = await encryptionFunction(
        bytes,
        key,
        Number.isNaN(nonce) ? 0n : BigInt(nonce),
      );

      processHolder.innerHTML = "";
      for (let i = 0; i < partialOutputs.length; ++i) {
        const [title, content] = partialOutputs[i];
        const processDiv = document.createElement("div");
        processDiv.classList.add(
          "d-flex",
          "flex-column",
          "p-2",
          "mb-3",
          "border"
        );
        const processSpan = document.createElement("span");
        processSpan.classList.add("p");
        processSpan.textContent = title;

        const metadataContent = document.createElement("div");
        if (content != null && content.length > 0) {
          for (const line of content.split("\n")) {
            const metadataSpan = document.createElement("div");
            metadataSpan.classList.add("p", "text-primary");
            metadataSpan.textContent = line;
            metadataContent.appendChild(metadataSpan);
          }
        } else {
          processSpan.style.fontWeight = "bold";
        }

        processDiv.appendChild(processSpan);
        processDiv.appendChild(metadataContent);
        processHolder.appendChild(processDiv);
      }

      // Display the input, key, and output.

      inputResult.textContent = inputString;
      keyResult.textContent = resolvedKey;
      keyHashResult.textContent = keyHash.toString(16);
      outputResult.textContent = encrypted.toString(16);

      inputType.textContent = `(Plaintext)`;
      outputType.textContent = `(Hexadecimal)`;

      downloadText.classList.remove("d-none");
      break;
    }
    case "decrypt": {
      /// Since we want to encrypt, we need to do the following steps:
      ///  1. Convert the input string to bytes.
      ///  2. Encrypt the bytes using the TwoFish algorithm.
      ///  3. Convert the encrypted bytes to a hex string.
      ///  4. Display the hex string and the partial outputs.
      const decryptionFunction = decryptionFunctions[encryptionType] as EncryptDecrypt;

      let bytes: bigint;
      try {
        try {
          bytes = BigInt(`0x${inputString}`);
        } catch (e) {
          bytes = BigInt(inputString);
        }
      } catch (e) {
        alert("The input string is not a valid hex value.");
        return;
      }
      // const bytes = BigInt(`0x${inputString}`);
      const [partialOutputs, encrypted, resolvedKey, keyHash] = await decryptionFunction(
        bytes,
        key,
        Number.isNaN(nonce) ? 0n : BigInt(nonce),
      );

      processHolder.innerHTML = "";
      for (let i = 0; i < partialOutputs.length; ++i) {
        const [title, content] = partialOutputs[i];
        const processDiv = document.createElement("div");
        processDiv.classList.add(
          "d-flex",
          "flex-column",
          "p-2",
          "mb-3",
          "border"
        );
        const processSpan = document.createElement("span");
        processSpan.classList.add("p");
        processSpan.textContent = title;

        const metadataContent = document.createElement("div");
        if (content != null && content.length > 0) {
          for (const line of content.split("\n")) {
            const metadataSpan = document.createElement("div");
            metadataSpan.classList.add("p", "text-primary");
            metadataSpan.textContent = line;
            metadataContent.appendChild(metadataSpan);
          }
        } else {
          processSpan.style.fontWeight = "bold";
        }

        processDiv.appendChild(processSpan);
        processDiv.appendChild(metadataContent);
        processHolder.appendChild(processDiv);
      }

      // Display the input, key, and output.

      inputResult.textContent = inputString;
      keyResult.textContent = resolvedKey;
      keyHashResult.textContent = keyHash.toString(16);
      outputResult.textContent = bytesToString(encrypted);

      inputType.textContent = `(Hexadecimal)`;
      outputType.textContent = `(Plaintext)`;

      downloadText.classList.remove("d-none");
      break;
    }
  }
});