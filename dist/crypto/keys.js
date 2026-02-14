import { randomBytes } from "node:crypto";
function toBase64Url(bytes) {
    return Buffer.from(bytes)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}
export function generateKeyId() {
    return `lk_${toBase64Url(randomBytes(18))}`;
}
export function generateSecret() {
    return `ls_${toBase64Url(randomBytes(32))}`;
}
//# sourceMappingURL=keys.js.map