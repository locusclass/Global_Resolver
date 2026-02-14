import bcrypt from "bcryptjs";
export async function hashSecret(secret) {
    return bcrypt.hash(secret, 12);
}
export async function verifySecret(secret, hash) {
    try {
        return await bcrypt.compare(secret, hash);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=hash.js.map