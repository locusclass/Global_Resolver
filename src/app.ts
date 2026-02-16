import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";

import { query } from "./db/index.js";
import { signAccessToken } from "./auth/jwt.js";
import { generateKeyId, generateSecret } from "./crypto/keys.js";
import { hashSecret, verifySecret } from "./crypto/hash.js";

import {
  verifyPresenceProof,
  verifyObjectDraftSignature,
  cellIdFromLatLng,
  type PresenceProof,
  type LocusObjectDraft,
} from "./shared/index.js";

/* -------------------------------------------------- */
/* Schemas */
/* -------------------------------------------------- */

const registerDeveloperBody = z.object({
  email: z.string().email().optional().nullable(),
});

const createProjectBody = z.object({
  developer_id: z.string().uuid(),
  name: z.string().min(1).max(120),
});

const keyLabelBody = z.object({
  label: z.string().min(1).max(120).optional(),
});

const tokenBody = z.object({
  key_id: z.string().min(5),
  api_secret: z.string().min(5),
});

const resolveBody = z.object({
  presence: z.any(),
  includeHistory: z.boolean().optional().default(false),
});

const anchorBody = z.object({
  presence: z.any(),
  objectDraft: z.any(),
});

function scopesForTier(_: "free" | "pro"): string[] {
  return ["resolve", "anchor", "supersede"];
}

/* -------------------------------------------------- */
/* Build App */
/* -------------------------------------------------- */

export function buildApp(): FastifyInstance {
  const app = Fastify({ logger: true });

  app.register(cors, {
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
  });

  /* -------------------------------------------------- */
  /* Health */
  /* -------------------------------------------------- */

  app.get("/health", async () => ({ message: "ok" }));
  app.get("/v1/health", async () => ({ message: "ok" }));

  /* -------------------------------------------------- */
  /* Developer */
  /* -------------------------------------------------- */

  app.post("/v1/dev/register", async (request, reply) => {
    const body = registerDeveloperBody.parse(request.body ?? {});
    const rows = await query<{ id: string }>(
      "INSERT INTO developers(email) VALUES ($1) RETURNING id",
      [body.email ?? null]
    );
    return reply.send({ developer_id: rows[0].id });
  });

  /* -------------------------------------------------- */
  /* Projects */
  /* -------------------------------------------------- */

  app.post("/v1/projects", async (request, reply) => {
    const body = createProjectBody.parse(request.body ?? {});

    const rows = await query<{
      id: string;
      name: string;
      tier: "free" | "pro";
      created_at: Date;
    }>(
      `
      INSERT INTO projects(developer_id, name)
      VALUES ($1, $2)
      RETURNING id, name, tier, created_at
      `,
      [body.developer_id, body.name]
    );

    const project = rows[0];

    return reply.code(201).send({
      project_id: project.id,
      name: project.name,
      tier: project.tier,
      created_at: project.created_at.toISOString(),
    });
  });

  app.get("/v1/projects", async (request, reply) => {
    const developerId = (request.query as { developer_id?: string }).developer_id;

    if (!developerId) {
      return reply.code(400).send({ error: "developer_id is required" });
    }

    const rows = await query<{
      id: string;
      name: string;
      tier: "free" | "pro";
      created_at: Date;
    }>(
      `
      SELECT id, name, tier, created_at
      FROM projects
      WHERE developer_id = $1
      ORDER BY created_at DESC
      `,
      [developerId]
    );

    return reply.send({
      projects: rows.map((p) => ({
        project_id: p.id,
        name: p.name,
        tier: p.tier,
        created_at: p.created_at.toISOString(),
      })),
    });
  });

  /* -------------------------------------------------- */
  /* API Keys */
  /* -------------------------------------------------- */

  app.post("/v1/projects/:project_id/keys", async (request, reply) => {
    const projectId = (request.params as { project_id: string }).project_id;
    const body = keyLabelBody.parse(request.body ?? {});

    const keyId = generateKeyId();
    const secret = generateSecret();
    const secretHash = await hashSecret(secret);

    const rows = await query<{ created_at: Date }>(
      `
      INSERT INTO api_keys(project_id, label, key_id, secret_hash)
      VALUES ($1, $2, $3, $4)
      RETURNING created_at
      `,
      [projectId, body.label ?? "default", keyId, secretHash]
    );

    return reply.code(201).send({
      key_id: keyId,
      api_secret: secret,
      created_at: rows[0].created_at.toISOString(),
    });
  });

  app.get("/v1/projects/:project_id/keys", async (request, reply) => {
    const projectId = (request.params as { project_id: string }).project_id;

    const rows = await query<{
      id: string;
      label: string;
      key_id: string;
      created_at: Date;
      revoked_at: Date | null;
      last_used_at: Date | null;
    }>(
      `
      SELECT id, label, key_id, created_at, revoked_at, last_used_at
      FROM api_keys
      WHERE project_id = $1
      ORDER BY created_at DESC
      `,
      [projectId]
    );

    return reply.send({
      keys: rows.map((k) => ({
        id: k.id,
        label: k.label,
        key_id: k.key_id,
        created_at: k.created_at.toISOString(),
        revoked_at: k.revoked_at?.toISOString() ?? null,
        last_used_at: k.last_used_at?.toISOString() ?? null,
      })),
    });
  });

  app.post("/v1/projects/:project_id/keys/:key_id/rotate", async (request, reply) => {
    const { project_id, key_id } = request.params as {
      project_id: string;
      key_id: string;
    };

    const newSecret = generateSecret();
    const secretHash = await hashSecret(newSecret);

    await query(
      `
      UPDATE api_keys
      SET secret_hash = $1, revoked_at = NULL
      WHERE project_id = $2 AND key_id = $3
      `,
      [secretHash, project_id, key_id]
    );

    return reply.send({
      key_id,
      api_secret: newSecret,
      created_at: new Date().toISOString(),
    });
  });

  app.post("/v1/projects/:project_id/keys/:key_id/revoke", async (request, reply) => {
    const { project_id, key_id } = request.params as {
      project_id: string;
      key_id: string;
    };

    await query(
      `
      UPDATE api_keys
      SET revoked_at = now()
      WHERE project_id = $1 AND key_id = $2
      `,
      [project_id, key_id]
    );

    return reply.send({ success: true });
  });

  /* -------------------------------------------------- */
  /* Auth */
  /* -------------------------------------------------- */

  app.post("/v1/auth/token", async (request, reply) => {
    const body = tokenBody.parse(request.body ?? {});

    const rows = await query<{
      project_id: string;
      secret_hash: string;
      revoked_at: Date | null;
      tier: "free" | "pro";
    }>(
      `
      SELECT k.project_id, k.secret_hash, k.revoked_at, p.tier
      FROM api_keys k
      JOIN projects p ON p.id = k.project_id
      WHERE k.key_id = $1
      LIMIT 1
      `,
      [body.key_id]
    );

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
      tier: key.tier,
    });

    return reply.send({
      access_token: token,
      token_type: "Bearer",
      expires_in: 900,
      project_id: key.project_id,
      scopes,
    });
  });

  /* -------------------------------------------------- */
  /* Spatial Resolve */
  /* -------------------------------------------------- */

  app.post("/v1/resolve", async (request, reply) => {
    const body = resolveBody.parse(request.body ?? {});
    const presence = body.presence as PresenceProof;

    const valid = await verifyPresenceProof(presence);
    if (!valid) {
      return reply.code(400).send({ error: "Invalid presence proof" });
    }

    const cellId = cellIdFromLatLng(presence.lat, presence.lng, 10);

    const rows = await query<any>(
      `
      SELECT *
      FROM locus_objects
      WHERE cell_id = $1
      ORDER BY created_at DESC
      `,
      [cellId]
    );

    return reply.send({
      queryCellId: cellId,
      objects: rows,
    });
  });

  /* -------------------------------------------------- */
  /* Error Handler */
  /* -------------------------------------------------- */

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof z.ZodError) {
      return reply.code(400).send({
        error: error.issues.map((i) => i.message).join(", "),
      });
    }

    request.log.error(error);
    return reply.code(500).send({ error: "Internal server error" });
  });

  return app;
}
