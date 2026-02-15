import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";

import {
  cellIdFromLatLng,
  createObjectDraftHash,
  verifyObjectDraftSignature,
  verifyPresenceProof,
  type CanonicalJsonValue,
  type LocusObjectDraft,
  type PresenceProof
} from "./shared/index.js";

import { requireAuth } from "./auth/requireAuth.js";
import { query } from "./db/index.js";

/* ================================
   Schemas
================================ */

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

type StoredResolverObject = {
  object_id: string;
  schema_id: string;
  radius_m: number;
  payload: CanonicalJsonValue;
  cell_id: string;
  created_at: Date;
  parent_object_id: string | null;
  supersedes_object_id: string | null;
};

/* ================================
   Helpers
================================ */

function toResolverObject(item: StoredResolverObject) {
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

async function storeObject(params: {
  projectId: string;
  presence: PresenceProof;
  draft: LocusObjectDraft;
  parentObjectId: string | null;
  supersedesObjectId: string | null;
}): Promise<StoredResolverObject> {
  const cellId = cellIdFromLatLng(
    params.presence.lat,
    params.presence.lng,
    Number(process.env.H3_RESOLUTION ?? 10)
  );

  const payloadHash = await createObjectDraftHash({
    schema_id: params.draft.schema_id,
    radius_m: params.draft.radius_m,
    payload: params.draft.payload,
    creator_public_key: params.draft.creator_public_key
  });

  const rows = await query<StoredResolverObject>(
    `
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
      $1,$2,$3,$4::jsonb,$5,$6,$7,$8::jsonb,
      $9,$10,$11,$12,$13,$14
    )
    RETURNING object_id, schema_id, radius_m, payload, cell_id,
              created_at, parent_object_id, supersedes_object_id
    `,
    [
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
    ]
  );

  return rows[0];
}

/* ================================
   App Builder
================================ */

export function buildApp(): FastifyInstance {
  const app = Fastify({ logger: true });

  /* ---- CORS ---- */
  app.register(cors, { origin: true });

  /* ---- Health ---- */
  app.get("/health", async () => ({ message: "ok" }));
  app.get("/v1/health", async () => ({ message: "ok" }));

  /* ================================
     RESOLVE
  ================================ */

  app.post(
    "/v1/resolve",
    { preHandler: requireAuth("resolve") },
    async (request, reply) => {
      const body = resolveBody.parse(request.body ?? {});
      const projectId = (request as any).auth.projectId;

      const validPresence = await verifyPresenceProof(body.presence);
      if (!validPresence) {
        return reply.code(400).send({ error: "Invalid presence proof" });
      }

      const cellId = cellIdFromLatLng(
        body.presence.lat,
        body.presence.lng,
        Number(process.env.H3_RESOLUTION ?? 10)
      );

      const rows = await query<StoredResolverObject>(
        `
        SELECT object_id, schema_id, radius_m, payload, cell_id,
               created_at, parent_object_id, supersedes_object_id
        FROM resolver_objects
        WHERE project_id = $1
          AND cell_id = $2
        ORDER BY created_at DESC
        `,
        [projectId, cellId]
      );

      return reply.send({
        cell_id: cellId,
        objects: rows.map(toResolverObject)
      });
    }
  );

  /* ================================
     ANCHOR
  ================================ */

  app.post(
    "/v1/anchor",
    { preHandler: requireAuth("anchor") },
    async (request, reply) => {
      const body = anchorBody.parse(request.body ?? {});
      const projectId = (request as any).auth.projectId;

      const validPresence = await verifyPresenceProof(body.presence);
      if (!validPresence) {
        return reply.code(400).send({ error: "Invalid presence proof" });
      }

      const validSignature = await verifyObjectDraftSignature(body.objectDraft);
      if (!validSignature) {
        return reply.code(400).send({ error: "Invalid object signature" });
      }

      const stored = await storeObject({
        projectId,
        presence: body.presence,
        draft: body.objectDraft,
        parentObjectId: null,
        supersedesObjectId: null
      });

      return reply.code(201).send({
        object: toResolverObject(stored)
      });
    }
  );

  /* ================================
     SUPERSEDE
  ================================ */

  app.post(
    "/v1/supersede",
    { preHandler: requireAuth("supersede") },
    async (request, reply) => {
      const body = supersedeBody.parse(request.body ?? {});
      const projectId = (request as any).auth.projectId;

      const validPresence = await verifyPresenceProof(body.presence);
      if (!validPresence) {
        return reply.code(400).send({ error: "Invalid presence proof" });
      }

      const validSignature = await verifyObjectDraftSignature(body.objectDraft);
      if (!validSignature) {
        return reply.code(400).send({ error: "Invalid object signature" });
      }

      const stored = await storeObject({
        projectId,
        presence: body.presence,
        draft: body.objectDraft,
        parentObjectId: null,
        supersedesObjectId: body.supersedes_object_id
      });

      return reply.code(201).send({
        object: toResolverObject(stored)
      });
    }
  );

  /* ---- Error Handler ---- */
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof z.ZodError) {
      return reply.code(400).send({
        error: error.issues.map((i) => i.message).join(", ")
      });
    }
    request.log.error(error);
    return reply.code(500).send({ error: "Internal server error" });
  });

  return app;
}
