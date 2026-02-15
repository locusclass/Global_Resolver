export declare function hashSecret(secret: string): Promise<string>;
export declare function verifySecret(secret: string, hash: string): Promise<boolean>;
