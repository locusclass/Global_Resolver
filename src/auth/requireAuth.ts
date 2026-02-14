import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";

import { verifyAccessToken } from "./jwt.js";

export function requireAuth(requiredScope: string): preHandlerHookHandler {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const header = request.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
      return reply.code(401).send({ error: "Missing bearer token" });
    }

    const token = header.slice("Bearer ".length).trim();
    try {
      const claims = await verifyAccessToken(token);
      const scopes = claims.scopes;
      if (!scopes.includes(requiredScope)) {
        return reply.code(403).send({ error: "Insufficient scope" });
      }

      request.auth = {
        projectId: claims.pid,
        keyId: claims.kid,
        scopes,
        tier: claims.tier
      };
      return;
    } catch {
      return reply.code(401).send({ error: "Invalid token" });
    }
  };
}
