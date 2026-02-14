import { randomBytes } from "node:crypto";

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function generateKeyId(): string {
  return `lk_${toBase64Url(randomBytes(18))}`;
}

export function generateSecret(): string {
  return `ls_${toBase64Url(randomBytes(32))}`;
}
