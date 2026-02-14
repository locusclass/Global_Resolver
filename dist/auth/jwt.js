import { createHash, randomUUID } from "node:crypto";
import { exportSPKI, generateKeyPair, importPKCS8, importSPKI, jwtVerify, SignJWT } from "jose";
const ISSUER = process.env.LOCUS_JWT_ISS ?? "locus";
const AUDIENCE = process.env.LOCUS_JWT_AUD ?? "locus-resolver";
let privateKeyPromise = null;
let publicKeyPromise = null;
function isPem(value) {
    return value.includes("BEGIN ");
}
function normalizeBase64(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const mod = normalized.length % 4;
    return mod === 0 ? normalized : normalized + "=".repeat(4 - mod);
}
function derToPem(label, value) {
    const der = Buffer.from(normalizeBase64(value), "base64").toString("base64");
    const wrapped = der.match(/.{1,64}/g)?.join("\n") ?? der;
    return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}
function keyFingerprint(key) {
    return createHash("sha256").update(key).digest("hex").slice(0, 12);
}
async function loadKeys() {
    const privateRaw = process.env.LOCUS_JWT_PRIVATE_KEY;
    const publicRaw = process.env.LOCUS_JWT_PUBLIC_KEY;
    const isProd = process.env.NODE_ENV === "production";
    if (privateRaw && publicRaw) {
        const privatePem = isPem(privateRaw) ? privateRaw : derToPem("PRIVATE KEY", privateRaw);
        const publicPem = isPem(publicRaw) ? publicRaw : derToPem("PUBLIC KEY", publicRaw);
        return {
            privateKey: await importPKCS8(privatePem, "EdDSA"),
            publicKey: await importSPKI(publicPem, "EdDSA")
        };
    }
    if (isProd) {
        throw new Error("Missing LOCUS_JWT_PRIVATE_KEY/LOCUS_JWT_PUBLIC_KEY in production environment");
    }
    const generated = await generateKeyPair("EdDSA", { crv: "Ed25519", extractable: true });
    const publicPem = await exportSPKI(generated.publicKey);
    console.warn(`[locus] Using ephemeral JWT keypair (dev only), public fingerprint=${keyFingerprint(publicPem)}`);
    return {
        privateKey: generated.privateKey,
        publicKey: generated.publicKey
    };
}
async function getPrivateKey() {
    if (!privateKeyPromise) {
        const keys = loadKeys();
        privateKeyPromise = keys.then((value) => value.privateKey);
        publicKeyPromise = keys.then((value) => value.publicKey);
    }
    return privateKeyPromise;
}
async function getPublicKey() {
    if (!publicKeyPromise) {
        const keys = loadKeys();
        privateKeyPromise = keys.then((value) => value.privateKey);
        publicKeyPromise = keys.then((value) => value.publicKey);
    }
    return publicKeyPromise;
}
export async function signAccessToken(input) {
    const privateKey = await getPrivateKey();
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
        pid: input.projectId,
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
export async function verifyAccessToken(token) {
    const publicKey = await getPublicKey();
    const { payload } = await jwtVerify(token, publicKey, {
        issuer: ISSUER,
        audience: AUDIENCE
    });
    if (typeof payload.sub !== "string" || typeof payload.pid !== "string") {
        throw new Error("Invalid token subject");
    }
    if (!Array.isArray(payload.scopes)) {
        throw new Error("Invalid token scopes");
    }
    if (payload.tier !== "free" && payload.tier !== "pro") {
        throw new Error("Invalid token tier");
    }
    return payload;
}
//# sourceMappingURL=jwt.js.map