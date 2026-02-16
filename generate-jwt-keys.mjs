import { generateKeyPair } from "jose";
import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;

async function main() {
  // Generate extractable Ed25519 keypair
  const { privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true
  });

  // Export PKCS8 DER
  const pkcs8 = await subtle.exportKey("pkcs8", privateKey);

  // Convert to base64 (single line)
  const base64 = Buffer.from(pkcs8).toString("base64");

  console.log("\n===============================================");
  console.log("  LOCUS_JWT_PRIVATE_KEY (BASE64 DER FORMAT)");
  console.log("===============================================\n");
  console.log(base64);
  console.log("\n===============================================\n");
}

main().catch((err) => {
  console.error("Key generation failed:");
  console.error(err);
  process.exit(1);
});
