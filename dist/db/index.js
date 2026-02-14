import { Pool } from "pg";
const DEFAULT_DATABASE_URL = "postgres://locus:locus_dev_password@localhost:5432/locus_class";
export const pool = new Pool({
    connectionString: process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL
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
//# sourceMappingURL=index.js.map