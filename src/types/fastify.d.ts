import "fastify";

declare module "fastify" {
  interface FastifyRequest {
    auth?: {
      projectId: string;
      keyId: string;
      scopes: string[];
      tier: "free" | "pro";
    };
  }
}
