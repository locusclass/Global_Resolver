import { verifyAccessToken } from "./jwt.js";
export function requireAuth(requiredScope) {
    return async (request, reply) => {
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
                scopes,
                tier: claims.tier
            };
            return;
        }
        catch {
            return reply.code(401).send({ error: "Invalid token" });
        }
    };
}
//# sourceMappingURL=requireAuth.js.map