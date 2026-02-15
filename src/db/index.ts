import { Pool, type PoolClient, type QueryResult } from "pg";

const DEFAULT_DATABASE_URL =
  "postgres://locus:locus_dev_password@localhost:5432/locus_class";

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL,
});

export async function withClient<T>(
  fn: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function query<T = unknown>(
  text: string,
  values?: readonly unknown[]
): Promise<T[]> {
  let result: QueryResult;

  if (values && values.length > 0) {
    result = await pool.query(text, values as any[]);
  } else {
    result = await pool.query(text);
  }

  return result.rows as T[];
}
