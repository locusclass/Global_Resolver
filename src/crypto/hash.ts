import bcrypt from "bcryptjs";

export async function hashSecret(secret: string): Promise<string> {
  return bcrypt.hash(secret, 12);
}

export async function verifySecret(secret: string, hash: string): Promise<boolean> {
  try {
    return await bcrypt.compare(secret, hash);
  } catch {
    return false;
  }
}
