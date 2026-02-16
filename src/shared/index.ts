import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  sign,
  verify
} from "node:crypto";

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

export type PresenceProof = {
  algorithm: "ed25519";
  signer_public_key: string;
  payload_hash: string;
  signature: string;
  lat: number;
  lng: number;
  accuracy_m: number;
  timestamp_ms: number;
  nonce: string;
};

export type LocusObjectDraft = {
  schema_id: string;
  radius_m: number;
  payload: CanonicalJsonValue;
  creator_public_key: string;
  creator_signature: string;
};

type PresencePayload = Omit<
  PresenceProof,
  "algorithm" | "payload_hash" | "signature"
>;
type ObjectDraftPayload = Omit<LocusObjectDraft, "creator_signature">;

/* -------------------------------------------------- */
/* Helpers */
/* -------------------------------------------------- */

function stableStringify(value: CanonicalJsonValue): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map(
      (key) =>
        `${JSON.stringify(key)}:${stableStringify(value[key] ?? null)}`
    )
    .join(",")}}`;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function normalizeBase64UrlToBase64(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const mod = normalized.length % 4;
  return mod === 0 ? normalized : normalized + "=".repeat(4 - mod);
}

/* -------------------------------------------------- */
/* Key Decoding */
/* -------------------------------------------------- */

function decodeKey(keyString: string, type: "public" | "private") {
  const normalized = normalizeBase64UrlToBase64(keyString);
  const buffer = Buffer.from(normalized, "base64");

  if (type === "public") {
    // If raw 32-byte Ed25519 key, wrap in SPKI
    if (buffer.length === 32) {
      // SPKI prefix for Ed25519:
      // 302a300506032b6570032100
      const spkiPrefix = Buffer.from(
        "302a300506032b6570032100",
        "hex"
      );
      const spkiDer = Buffer.concat([spkiPrefix, buffer]);
      return createPublicKey({
        key: spkiDer,
        format: "der",
        type: "spki"
      });
    }

    // Otherwise assume already SPKI DER
    return createPublicKey({
      key: buffer,
      format: "der",
      type: "spki"
    });
  }

  // Private keys remain PKCS8 DER
  return createPrivateKey({
    key: buffer,
    format: "der",
    type: "pkcs8"
  });
}

/* -------------------------------------------------- */
/* Ed25519 Key Generation */
/* -------------------------------------------------- */

export async function generateEd25519KeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      "ed25519",
      {
        publicKeyEncoding: { format: "der", type: "spki" },
        privateKeyEncoding: { format: "der", type: "pkcs8" }
      },
      (error, publicKey, privateKey) => {
        if (error) {
          reject(error);
          return;
        }
        resolve({
          publicKey: Buffer.from(publicKey).toString("base64"),
          privateKey: Buffer.from(privateKey).toString("base64")
        });
      }
    );
  });
}

/* -------------------------------------------------- */
/* Signing & Verification */
/* -------------------------------------------------- */

export async function signEd25519(
  payloadHash: string,
  privateKey: string
): Promise<string> {
  const key = decodeKey(privateKey, "private");
  const signature = sign(
    null,
    Buffer.from(payloadHash, "hex"),
    key
  );
  return signature.toString("base64");
}

export async function verifyEd25519(
  payloadHash: string,
  signatureBase64: string,
  publicKey: string
): Promise<boolean> {
  const key = decodeKey(publicKey, "public");
  return verify(
    null,
    Buffer.from(payloadHash, "hex"),
    key,
    Buffer.from(normalizeBase64UrlToBase64(signatureBase64), "base64")
  );
}

/* -------------------------------------------------- */
/* Presence Verification */
/* -------------------------------------------------- */

export async function createPresencePayloadHash(
  payload: PresencePayload
): Promise<string> {
  return sha256Hex(stableStringify(payload));
}

export async function createObjectDraftHash(
  payload: ObjectDraftPayload
): Promise<string> {
  return sha256Hex(stableStringify(payload));
}

export async function verifyPresenceProof(
  presence: PresenceProof
): Promise<boolean> {
  if (presence.algorithm !== "ed25519") {
    return false;
  }

  const payload: PresencePayload = {
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

  return verifyEd25519(
    presence.payload_hash,
    presence.signature,
    presence.signer_public_key
  );
}

export async function verifyObjectDraftSignature(
  draft: LocusObjectDraft
): Promise<boolean> {
  const payload: ObjectDraftPayload = {
    schema_id: draft.schema_id,
    radius_m: draft.radius_m,
    payload: draft.payload,
    creator_public_key: draft.creator_public_key
  };

  const payloadHash = await createObjectDraftHash(payload);

  return verifyEd25519(
    payloadHash,
    draft.creator_signature,
    draft.creator_public_key
  );
}

/* -------------------------------------------------- */
/* Cell ID */
/* -------------------------------------------------- */

export function cellIdFromLatLng(
  lat: number,
  lng: number,
  resolution: number
): string {
  const clampedResolution = Number.isFinite(resolution)
    ? Math.max(1, Math.min(15, Math.round(resolution)))
    : 10;

  const factor = Math.pow(
    10,
    Math.max(1, Math.min(6, clampedResolution))
  );

  const latBucket = Math.round(lat * factor) / factor;
  const lngBucket = Math.round(lng * factor) / factor;

  return `cell_${clampedResolution}_${latBucket.toFixed(
    6
  )}_${lngBucket.toFixed(6)}`;
}
