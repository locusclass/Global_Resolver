import { generateKeyPair } from "jose";
import { exportPKCS8, exportSPKI } from "jose";

const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
  crv: "Ed25519",
  extractable: true   // <-- THIS FIXES YOUR ERROR
});

const privatePem = await exportPKCS8(privateKey);
const publicPem = await exportSPKI(publicKey);

console.log("\n================ PRIVATE KEY ================\n");
console.log(privatePem);

console.log("\n================ PUBLIC KEY ================\n");
console.log(publicPem);
