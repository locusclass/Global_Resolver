import { generateKeyPair, exportPKCS8, exportSPKI } from "jose";

const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
  crv: "Ed25519",
});

const privatePem = await exportPKCS8(privateKey);
const publicPem = await exportSPKI(publicKey);

console.log("PRIVATE KEY:\n");
console.log(privatePem);

console.log("\nPUBLIC KEY:\n");
console.log(publicPem);
