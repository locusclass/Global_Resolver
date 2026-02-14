import { Pool, type PoolClient, type QueryResultRow } from "pg";

const DEFAULT_DATABASE_URL =
  "postgres://locus:locus_dev_password@localhost:5432/locus_class";

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL
});

export async function withClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  values?: readonly unknown[]
): Promise<T[]> {
  const result = await pool.query<T>(text, values as unknown[] | undefined);
  return result.rows;
}
