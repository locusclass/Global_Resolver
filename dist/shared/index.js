import { createHash, createPrivateKey, createPublicKey, generateKeyPair, sign, verify } from "node:crypto";
function stableStringify(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map((item) => stableStringify(item)).join(",")}]`;
    }
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key] ?? null)}`).join(",")}}`;
}
function sha256Hex(input) {
    return createHash("sha256").update(input).digest("hex");
}
function decodeKey(keyBase64, type) {
    const buffer = Buffer.from(keyBase64, "base64");
    if (type === "public") {
        return createPublicKey({ key: buffer, format: "der", type: "spki" });
    }
    return createPrivateKey({ key: buffer, format: "der", type: "pkcs8" });
}
export async function generateEd25519KeyPair() {
    return new Promise((resolve, reject) => {
        generateKeyPair("ed25519", { publicKeyEncoding: { format: "der", type: "spki" }, privateKeyEncoding: { format: "der", type: "pkcs8" } }, (error, publicKey, privateKey) => {
            if (error) {
                reject(error);
                return;
            }
            resolve({
                publicKey: Buffer.from(publicKey).toString("base64"),
                privateKey: Buffer.from(privateKey).toString("base64")
            });
        });
    });
}
export async function signEd25519(payloadHash, privateKey) {
    const key = decodeKey(privateKey, "private");
    const signature = sign(null, Buffer.from(payloadHash, "hex"), key);
    return signature.toString("base64");
}
export async function verifyEd25519(payloadHash, signatureBase64, publicKey) {
    const key = decodeKey(publicKey, "public");
    return verify(null, Buffer.from(payloadHash, "hex"), key, Buffer.from(signatureBase64, "base64"));
}
export async function createPresencePayloadHash(payload) {
    return sha256Hex(stableStringify(payload));
}
export async function createObjectDraftHash(payload) {
    return sha256Hex(stableStringify(payload));
}
export async function verifyPresenceProof(presence) {
    if (presence.algorithm !== "ed25519") {
        return false;
    }
    const payload = {
        lat: presence.lat,
        lng: presence.lng,
        accuracy_m: presence.accuracy_m,
        timestamp_ms: presence.timestamp_ms,
        nonce: presence.nonce,
        signer_public_key: presence.signer_public_key
    };
    const payloadHash = await createPresencePayloadHash(payload);
    if (payloadHash !== presence.payload_hash) {
        return false;
    }
    return verifyEd25519(presence.payload_hash, presence.signature, presence.signer_public_key);
}
export async function verifyObjectDraftSignature(draft) {
    const payload = {
        schema_id: draft.schema_id,
        radius_m: draft.radius_m,
        payload: draft.payload,
        creator_public_key: draft.creator_public_key
    };
    const payloadHash = await createObjectDraftHash(payload);
    return verifyEd25519(payloadHash, draft.creator_signature, draft.creator_public_key);
}
export function cellIdFromLatLng(lat, lng, resolution) {
    const clampedResolution = Number.isFinite(resolution) ? Math.max(1, Math.min(15, Math.round(resolution))) : 10;
    const factor = Math.pow(10, Math.max(1, Math.min(6, clampedResolution)));
    const latBucket = Math.round(lat * factor) / factor;
    const lngBucket = Math.round(lng * factor) / factor;
    return `cell_${clampedResolution}_${latBucket.toFixed(6)}_${lngBucket.toFixed(6)}`;
}
