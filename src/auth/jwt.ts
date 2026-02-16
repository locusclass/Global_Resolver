import { randomUUID } from "node:crypto";
import {
  generateKeyPair,
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

type JwtPrivateKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
type JwtPublicKey = Awaited<ReturnType<typeof generateKeyPair>>["publicKey"];

let privateKeyPromise: Promise<JwtPrivateKey> | null = null;
let publicKeyPromise: Promise<JwtPublicKey> | null = null;

/* -------------------------------------------------- */
/* Key Loader (Runtime Generated – No ENV Required) */
/* -------------------------------------------------- */

async function loadKeys(): Promise<{
  privateKey: JwtPrivateKey;
  publicKey: JwtPublicKey;
}> {
  const generated = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: false
  });

  console.warn("[locus] Runtime JWT keypair generated");

  return {
    privateKey: generated.privateKey,
    publicKey: generated.publicKey
  };
}

async function getPrivateKey(): Promise<JwtPrivateKey> {
  if (!privateKeyPromise) {
    const keys = loadKeys();
    privateKeyPromise = keys.then((k) => k.privateKey);
    publicKeyPromise = keys.then((k) => k.publicKey);
  }
  return privateKeyPromise;
}

async function getPublicKey(): Promise<JwtPublicKey> {
  if (!publicKeyPromise) {
    const keys = loadKeys();
    privateKeyPromise = keys.then((k) => k.privateKey);
    publicKeyPromise = keys.then((k) => k.publicKey);
  }
  return publicKeyPromise;
}

/* -------------------------------------------------- */
/* Sign Access Token */
/* -------------------------------------------------- */

export async function signAccessToken(
  input: AccessTokenInput
): Promise<string> {
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

export async function verifyAccessToken(
  token: string
): Promise<AccessTokenClaims> {
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
