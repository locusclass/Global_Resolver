import { Pool, type PoolClient } from "pg";
export declare const pool: Pool;
export declare function withClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T>;
export declare function query<T = unknown>(text: string, values?: readonly unknown[]): Promise<T[]>;
