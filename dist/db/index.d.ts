import { Pool, type PoolClient, type QueryResultRow } from "pg";
export declare const pool: Pool;
export declare function withClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T>;
export declare function query<T extends QueryResultRow = QueryResultRow>(text: string, values?: readonly unknown[]): Promise<T[]>;
//# sourceMappingURL=index.d.ts.map