import { createHash, randomUUID } from "node:crypto";

import {
  exportSPKI,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
  type JWTPayload
} from "jose";

const ISSUER = process.env.LOCUS_JWT_ISS ?? "locus";
const AUDIENCE = process.env.LOCUS_JWT_AUD ?? "locus-resolver";

export type AccessTokenInput = {
  projectId: string;
  keyId: string;
  scopes: string[];
  tier: "free" | "pro";
};

export type AccessTokenClaims = JWTPayload & {
  pid: string;
  kid: string;
  scopes: string[];
  tier: "free" | "pro";
};

type JwtPrivateKey = Awaited<ReturnType<typeof importPKCS8>>;
type JwtPublicKey = Awaited<ReturnType<typeof importSPKI>>;

let privateKeyPromise: Promise<JwtPrivateKey> | null = null;
let publicKeyPromise: Promise<JwtPublicKey> | null = null;

/* -------------------------------------------------- */
/* Helpers */
/* -------------------------------------------------- */

function isPem(value: string): boolean {
  return value.includes("BEGIN ");
}

function normalizeBase64(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const mod = normalized.length % 4;
  return mod === 0 ? normalized : normalized + "=".repeat(4 - mod);
}

function derToPem(label: "PRIVATE KEY" | "PUBLIC KEY", value: string): string {
  const der = Buffer.from(normalizeBase64(value), "base64").toString("base64");
  const wrapped = der.match(/.{1,64}/g)?.join("\n") ?? der;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

function normalizePemInput(value: string): string {
  // Fix Railway escaped newlines
  return value.replace(/\\n/g, "\n").trim();
}

function keyFingerprint(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 12);
}

/* -------------------------------------------------- */
/* Key Loader */
/* -------------------------------------------------- */

async function loadKeys(): Promise<{ privateKey: JwtPrivateKey; publicKey: JwtPublicKey }> {
  const privateRaw = process.env.LOCUS_JWT_PRIVATE_KEY;
  const publicRaw = process.env.LOCUS_JWT_PUBLIC_KEY;
  const isProd = process.env.NODE_ENV === "production";

  if (privateRaw && publicRaw) {
    const privateNormalized = normalizePemInput(privateRaw);
    const publicNormalized = normalizePemInput(publicRaw);

    const privatePem = isPem(privateNormalized)
      ? privateNormalized
      : derToPem("PRIVATE KEY", privateNormalized);

    const publicPem = isPem(publicNormalized)
      ? publicNormalized
      : derToPem("PUBLIC KEY", publicNormalized);

    return {
      privateKey: await importPKCS8(privatePem, "EdDSA"),
      publicKey: await importSPKI(publicPem, "EdDSA")
    };
  }

  if (isProd) {
    throw new Error(
      "Missing LOCUS_JWT_PRIVATE_KEY/LOCUS_JWT_PUBLIC_KEY in production environment"
    );
  }

  // Dev fallback (ephemeral keypair)
  const generated = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true
  });

  const publicPem = await exportSPKI(generated.publicKey);

  console.warn(
    `[locus] Using ephemeral JWT keypair (dev only), public fingerprint=${keyFingerprint(
      publicPem
    )}`
  );

  return {
    privateKey: generated.privateKey,
    publicKey: generated.publicKey
  };
}

/* -------------------------------------------------- */
/* Key Accessors */
/* -------------------------------------------------- */

async function getPrivateKey(): Promise<JwtPrivateKey> {
  if (!privateKeyPromise) {
    const keys = loadKeys();
    privateKeyPromise = keys.then((value) => value.privateKey);
    publicKeyPromise = keys.then((value) => value.publicKey);
  }
  return privateKeyPromise;
}

async function getPublicKey(): Promise<JwtPublicKey> {
  if (!publicKeyPromise) {
    const keys = loadKeys();
    privateKeyPromise = keys.then((value) => value.privateKey);
    publicKeyPromise = keys.then((value) => value.publicKey);
  }
  return publicKeyPromise;
}

/* -------------------------------------------------- */
/* Sign Access Token */
/* -------------------------------------------------- */

export async function signAccessToken(input: AccessTokenInput): Promise<string> {
  const privateKey = await getPrivateKey();
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({
    pid: input.projectId,
    kid: input.keyId,
    scopes: input.scopes,
    tier: input.tier
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT" })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject(input.projectId)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 900)
    .sign(privateKey);
}

/* -------------------------------------------------- */
/* Verify Access Token */
/* -------------------------------------------------- */

export async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  const publicKey = await getPublicKey();

  const { payload } = await jwtVerify(token, publicKey, {
    issuer: ISSUER,
    audience: AUDIENCE
  });

  if (
    typeof payload.sub !== "string" ||
    typeof payload.pid !== "string" ||
    typeof payload.kid !== "string"
  ) {
    throw new Error("Invalid token subject");
  }

  if (!Array.isArray(payload.scopes)) {
    throw new Error("Invalid token scopes");
  }

  if (payload.tier !== "free" && payload.tier !== "pro") {
    throw new Error("Invalid token tier");
  }

  return payload as AccessTokenClaims;
}
