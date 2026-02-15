import { pool } from "./db/index.js";
import { migrateUp } from "./db/migrate.js";
import { buildApp } from "./app.js";
const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "0.0.0.0";
async function main() {
    await migrateUp();
    const app = buildApp();
    const shutdown = async () => {
        await app.close();
        await pool.end();
        process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
    await app.listen({ port, host });
}
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
