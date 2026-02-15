import { Pool } from "pg";
const isProduction = process.env.NODE_ENV === "production";
if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL environment variable is not set");
}
export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isProduction ? { rejectUnauthorized: false } : false
});
export async function withClient(fn) {
    const client = await pool.connect();
    try {
        return await fn(client);
    }
    finally {
        client.release();
    }
}
export async function query(text, values) {
    const result = await pool.query(text, values);
    return result.rows;
}
