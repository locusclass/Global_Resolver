import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";
import { signAccessToken } from "./auth/jwt.js";
import { verifySecret } from "./crypto/hash.js";
import { query } from "./db/index.js";
/* ----------------------------- SCHEMAS ----------------------------- */
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
/* ----------------------------- BUILD APP ----------------------------- */
export function buildApp() {
    const app = Fastify({ logger: true });
    /* ----------------------------- CORS FIX ----------------------------- */
    app.register(cors, {
        origin: true, // allow any origin (safe for API layer)
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    });
    /* ------------------------------------------------------------------- */
    /* ----------------------------- HEALTH ------------------------------- */
    app.get("/health", async () => ({ message: "ok" }));
    app.get("/v1/health", async () => ({ message: "ok" }));
    /* ----------------------- DEV + PROJECT ------------------------------ */
    app.post("/v1/dev/register", async (request, reply) => {
        const body = registerDeveloperBody.parse(request.body ?? {});
        const rows = await query("INSERT INTO developers(email) VALUES ($1) RETURNING id", [body.email ?? null]);
        return reply.send({ developer_id: rows[0].id });
    });
    app.post("/v1/projects", async (request, reply) => {
        const body = createProjectBody.parse(request.body ?? {});
        const rows = await query(`INSERT INTO projects(developer_id, name)
       VALUES ($1, $2)
       RETURNING id, name, tier, created_at`, [body.developer_id, body.name]);
        const project = rows[0];
        return reply.code(201).send({
            project_id: project.id,
            name: project.name,
            tier: project.tier,
            created_at: project.created_at.toISOString()
        });
    });
    /* ----------------------------- AUTH -------------------------------- */
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
        const scopes = ["resolve", "anchor", "supersede"];
        const token = await signAccessToken({
            projectId: key.project_id,
            keyId: body.key_id,
            scopes,
            tier: key.tier
        });
        return reply.send({
            access_token: token,
            token_type: "Bearer",
            expires_in: 900,
            project_id: key.project_id,
            scopes
        });
    });
    /* --------------------------- ERROR HANDLER -------------------------- */
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
