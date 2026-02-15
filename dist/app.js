import { randomUUID } from "node:crypto";
import { cellIdFromLatLng, createObjectDraftHash, verifyObjectDraftSignature, verifyPresenceProof } from "./shared/index.js";
import Fastify from "fastify";
import { z } from "zod";
import { requireAuth } from "./auth/requireAuth.js";
import { checkRateLimit } from "./auth/rateLimit.js";
import { signAccessToken } from "./auth/jwt.js";
import { generateKeyId, generateSecret } from "./crypto/keys.js";
import { hashSecret, verifySecret } from "./crypto/hash.js";
import { query } from "./db/index.js";
const registerDeveloperBody = z.object({
    email: z.string().email().optional().nullable()
});
const createProjectBody = z.object({
    developer_id: z.string().uuid(),
    name: z.string().min(1).max(120)
});
const keyLabelBody = z.object({
    label: z.string().min(1).max(120).optional()
});
const tokenBody = z.object({
    key_id: z.string().min(5),
    api_secret: z.string().min(5)
});
const presenceSchema = z.object({
    algorithm: z.literal("ed25519"),
    signer_public_key: z.string(),
    payload_hash: z.string(),
    signature: z.string(),
    lat: z.number(),
    lng: z.number(),
    accuracy_m: z.number(),
    timestamp_ms: z.number().int(),
    nonce: z.string()
});
const objectDraftSchema = z.object({
    schema_id: z.string().min(1),
    radius_m: z.number().positive(),
    payload: z.unknown(),
    creator_public_key: z.string(),
    creator_signature: z.string()
});
const resolveBody = z.object({
    presence: presenceSchema,
    includeHistory: z.boolean().optional().default(false)
});
const anchorBody = z.object({
    presence: presenceSchema,
    objectDraft: objectDraftSchema
});
const supersedeBody = z.object({
    presence: presenceSchema,
    supersedes_object_id: z.string().uuid(),
    objectDraft: objectDraftSchema
});
function scopesForTier(tier) {
    if (tier === "free") {
        return ["resolve", "anchor", "supersede"];
    }
    return ["resolve", "anchor", "supersede"];
}
function toResolverObject(item) {
    return {
        object_id: item.object_id,
        schema_id: item.schema_id,
        radius_m: item.radius_m,
        payload: item.payload,
        cell_id: item.cell_id,
        created_at: item.created_at.toISOString(),
        parent_object_id: item.parent_object_id,
        supersedes_object_id: item.supersedes_object_id
    };
}
async function storeObject(params) {
    const cellId = cellIdFromLatLng(params.presence.lat, params.presence.lng, Number(process.env.H3_RESOLUTION ?? 10));
    const payloadHash = await createObjectDraftHash({
        schema_id: params.draft.schema_id,
        radius_m: params.draft.radius_m,
        payload: params.draft.payload,
        creator_public_key: params.draft.creator_public_key
    });
    const rows = await query(`
      INSERT INTO resolver_objects (
        object_id,
        schema_id,
        radius_m,
        payload,
        payload_hash,
        creator_public_key,
        creator_signature,
        presence,
        cell_id,
        lat,
        lng,
        parent_object_id,
        supersedes_object_id,
        project_id
      )
      VALUES (
        $1,
        $2,
        $3,
        $4::jsonb,
        $5,
        $6,
        $7,
        $8::jsonb,
        $9,
        $10,
        $11,
        $12,
        $13,
        $14
      )
      RETURNING object_id, schema_id, radius_m, payload, cell_id, created_at, parent_object_id, supersedes_object_id
    `, [
        randomUUID(),
        params.draft.schema_id,
        params.draft.radius_m,
        JSON.stringify(params.draft.payload),
        payloadHash,
        params.draft.creator_public_key,
        params.draft.creator_signature,
        JSON.stringify(params.presence),
        cellId,
        params.presence.lat,
        params.presence.lng,
        params.parentObjectId,
        params.supersedesObjectId,
        params.projectId
    ]);
    return rows[0];
}
async function isKeyActive(projectId, keyId) {
    const rows = await query(`SELECT 1 as ok
     FROM api_keys
     WHERE project_id = $1 AND key_id = $2 AND revoked_at IS NULL
     LIMIT 1`, [projectId, keyId]);
    return rows.length > 0;
}
export function buildApp() {
    const app = Fastify({ logger: true });
    app.get("/health", async () => ({ message: "ok" }));
    app.get("/v1/health", async () => ({ message: "ok" }));
    app.post("/v1/dev/register", async (request, reply) => {
        const body = registerDeveloperBody.parse(request.body ?? {});
        const rows = await query("INSERT INTO developers(email) VALUES ($1) RETURNING id", [body.email ?? null]);
        return reply.send({ developer_id: rows[0].id });
    });
    app.post("/v1/projects", async (request, reply) => {
        const body = createProjectBody.parse(request.body ?? {});
        const rows = await query(`INSERT INTO projects(developer_id, name) VALUES ($1, $2)
       RETURNING id, name, tier, created_at`, [body.developer_id, body.name]);
        const project = rows[0];
        return reply.code(201).send({
            project_id: project.id,
            name: project.name,
            tier: project.tier,
            created_at: project.created_at.toISOString()
        });
    });
    app.get("/v1/projects", async (request, reply) => {
        const developerId = request.query.developer_id;
        if (!developerId) {
            return reply.code(400).send({ error: "developer_id is required" });
        }
        const rows = await query("SELECT id, name, tier, created_at FROM projects WHERE developer_id = $1 ORDER BY created_at DESC", [developerId]);
        return reply.send({
            projects: rows.map((project) => ({
                project_id: project.id,
                name: project.name,
                tier: project.tier,
                created_at: project.created_at.toISOString()
            }))
        });
    });
    app.post("/v1/projects/:project_id/keys", async (request, reply) => {
        const projectId = request.params.project_id;
        const body = keyLabelBody.parse(request.body ?? {});
        const keyId = generateKeyId();
        const secret = generateSecret();
        const secretHash = await hashSecret(secret);
        const rows = await query(`INSERT INTO api_keys(project_id, label, key_id, secret_hash)
       VALUES ($1, $2, $3, $4)
       RETURNING created_at`, [projectId, body.label ?? "default", keyId, secretHash]);
        return reply.code(201).send({
            key_id: keyId,
            api_secret: secret,
            created_at: rows[0].created_at.toISOString()
        });
    });
    app.get("/v1/projects/:project_id/keys", async (request, reply) => {
        const projectId = request.params.project_id;
        const rows = await query(`SELECT id, label, key_id, created_at, revoked_at, last_used_at
       FROM api_keys
       WHERE project_id = $1
       ORDER BY created_at DESC`, [projectId]);
        return reply.send({
            keys: rows.map((item) => ({
                id: item.id,
                label: item.label,
                key_id: item.key_id,
                created_at: item.created_at.toISOString(),
                revoked_at: item.revoked_at?.toISOString() ?? null,
                last_used_at: item.last_used_at?.toISOString() ?? null
            }))
        });
    });
    app.post("/v1/projects/:project_id/keys/:key_id/rotate", async (request, reply) => {
        const { project_id: projectId, key_id: keyId } = request.params;
        const secret = generateSecret();
        const secretHash = await hashSecret(secret);
        const rows = await query(`UPDATE api_keys
       SET secret_hash = $1, revoked_at = NULL, created_at = now()
       WHERE project_id = $2 AND key_id = $3
       RETURNING key_id, created_at`, [secretHash, projectId, keyId]);
        if (rows.length === 0) {
            return reply.code(404).send({ error: "Key not found" });
        }
        return reply.send({
            key_id: rows[0].key_id,
            api_secret: secret,
            created_at: rows[0].created_at.toISOString()
        });
    });
    app.post("/v1/projects/:project_id/keys/:key_id/revoke", async (request, reply) => {
        const { project_id: projectId, key_id: keyId } = request.params;
        await query(`UPDATE api_keys SET revoked_at = now() WHERE project_id = $1 AND key_id = $2`, [projectId, keyId]);
        return reply.send({ ok: true });
    });
    app.post("/v1/auth/token", async (request, reply) => {
        const body = tokenBody.parse(request.body ?? {});
        const rows = await query(`SELECT k.project_id, k.secret_hash, k.revoked_at, p.tier
       FROM api_keys k
       JOIN projects p ON p.id = k.project_id
       WHERE k.key_id = $1
       LIMIT 1`, [body.key_id]);
        if (rows.length === 0) {
            return reply.code(401).send({ error: "Invalid credentials" });
        }
        const key = rows[0];
        if (key.revoked_at) {
            return reply.code(401).send({ error: "Key revoked" });
        }
        const valid = await verifySecret(body.api_secret, key.secret_hash);
        if (!valid) {
            return reply.code(401).send({ error: "Invalid credentials" });
        }
        const scopes = scopesForTier(key.tier);
        const token = await signAccessToken({
            projectId: key.project_id,
            keyId: body.key_id,
            scopes,
            tier: key.tier
        });
        await query("UPDATE api_keys SET last_used_at = now() WHERE key_id = $1", [body.key_id]);
        return reply.send({
            access_token: token,
            token_type: "Bearer",
            expires_in: 900,
            project_id: key.project_id,
            scopes
        });
    });
    app.post("/v1/resolve", { preHandler: requireAuth("resolve") }, async (request, reply) => {
        const body = resolveBody.parse(request.body ?? {});
        const auth = request.auth;
        if (!auth) {
            return reply.code(401).send({ error: "Unauthorized" });
        }
        if (!(await isKeyActive(auth.projectId, auth.keyId))) {
            return reply.code(401).send({ error: "Key revoked" });
        }
        if (!checkRateLimit(auth.projectId, "resolve")) {
            return reply.code(429).send({ error: "Rate limit exceeded" });
        }
        const isPresenceValid = await verifyPresenceProof(body.presence);
        if (!isPresenceValid) {
            return reply.code(400).send({ error: "Invalid presence proof" });
        }
        const cellId = cellIdFromLatLng(body.presence.lat, body.presence.lng, Number(process.env.H3_RESOLUTION ?? 10));
        const rows = await query(`SELECT object_id, schema_id, radius_m, payload, cell_id, created_at, parent_object_id, supersedes_object_id
       FROM resolver_objects
       WHERE project_id = $1 AND cell_id = $2
       ORDER BY created_at DESC
       LIMIT $3`, [auth.projectId, cellId, body.includeHistory ? 100 : 25]);
        return reply.send({
            query: {
                cell_id: cellId
            },
            objects: rows.map((item) => toResolverObject(item))
        });
    });
    app.post("/v1/anchor", { preHandler: requireAuth("anchor") }, async (request, reply) => {
        const body = anchorBody.parse(request.body ?? {});
        const auth = request.auth;
        if (!auth) {
            return reply.code(401).send({ error: "Unauthorized" });
        }
        if (!(await isKeyActive(auth.projectId, auth.keyId))) {
            return reply.code(401).send({ error: "Key revoked" });
        }
        if (!checkRateLimit(auth.projectId, "anchor")) {
            return reply.code(429).send({ error: "Rate limit exceeded" });
        }
        const presence = body.presence;
        const draft = body.objectDraft;
        if (!(await verifyPresenceProof(presence))) {
            return reply.code(400).send({ error: "Invalid presence proof" });
        }
        if (!(await verifyObjectDraftSignature(draft))) {
            return reply.code(400).send({ error: "Invalid object draft signature" });
        }
        const stored = await storeObject({
            projectId: auth.projectId,
            presence,
            draft,
            parentObjectId: null,
            supersedesObjectId: null
        });
        return reply.code(201).send({ object: toResolverObject(stored) });
    });
    app.post("/v1/supersede", { preHandler: requireAuth("supersede") }, async (request, reply) => {
        const body = supersedeBody.parse(request.body ?? {});
        const auth = request.auth;
        if (!auth) {
            return reply.code(401).send({ error: "Unauthorized" });
        }
        if (!(await isKeyActive(auth.projectId, auth.keyId))) {
            return reply.code(401).send({ error: "Key revoked" });
        }
        if (!checkRateLimit(auth.projectId, "supersede")) {
            return reply.code(429).send({ error: "Rate limit exceeded" });
        }
        const presence = body.presence;
        const draft = body.objectDraft;
        if (!(await verifyPresenceProof(presence))) {
            return reply.code(400).send({ error: "Invalid presence proof" });
        }
        if (!(await verifyObjectDraftSignature(draft))) {
            return reply.code(400).send({ error: "Invalid object draft signature" });
        }
        const target = await query("SELECT object_id FROM resolver_objects WHERE object_id = $1 AND project_id = $2", [body.supersedes_object_id, auth.projectId]);
        if (target.length === 0) {
            return reply.code(404).send({ error: "supersedes_object_id not found" });
        }
        const stored = await storeObject({
            projectId: auth.projectId,
            presence,
            draft,
            parentObjectId: body.supersedes_object_id,
            supersedesObjectId: body.supersedes_object_id
        });
        return reply.code(201).send({ object: toResolverObject(stored) });
    });
    app.setErrorHandler((error, request, reply) => {
        if (error instanceof z.ZodError) {
            return reply.code(400).send({ error: error.issues.map((item) => item.message).join(", ") });
        }
        request.log?.error(error);
        return reply.code(500).send({ error: "Internal server error" });
    });
    return app;
}
