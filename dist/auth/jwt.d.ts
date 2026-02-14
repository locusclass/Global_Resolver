import { type JWTPayload } from "jose";
export type AccessTokenInput = {
    projectId: string;
    scopes: string[];
    tier: "free" | "pro";
};
export type AccessTokenClaims = JWTPayload & {
    pid: string;
    scopes: string[];
    tier: "free" | "pro";
};
export declare function signAccessToken(input: AccessTokenInput): Promise<string>;
export declare function verifyAccessToken(token: string): Promise<AccessTokenClaims>;
//# sourceMappingURL=jwt.d.ts.map