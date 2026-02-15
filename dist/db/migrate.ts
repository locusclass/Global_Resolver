import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { withClient } from "./index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Resolve migrations directory safely for both:
 * - development (tsx -> src/db/migrations)
 * - production (node dist -> dist/db/migrations)
 */
async function resolveMigrationsDir(): Promise<string | null> {
  const candidate = path.join(__dirname, "migrations");

  try {
    await fs.access(candidate);
    return candidate;
  } catch {
    console.warn("No migrations directory found at:", candidate);
    return null;
  }
}

async function ensureMigrationsTable(client: any) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);
}

async function listMigrationFiles(migrationsDir: string) {
  const files = await fs.readdir(migrationsDir);
  return files
    .filter((name) => name.endsWith(".sql"))
    .sort();
}

export async function migrateUp() {
  const migrationsDir = await resolveMigrationsDir();

  if (!migrationsDir) {
    console.warn("Skipping migrations: directory not found.");
    return;
  }

  await withClient(async (client) => {
    await ensureMigrationsTable(client);

    const appliedRows = await client.query(
      "SELECT version FROM schema_migrations"
    );
    const applied = new Set(
      appliedRows.rows.map((row: any) => row.version)
    );

    const files = await listMigrationFiles(migrationsDir);

    for (const file of files) {
      if (applied.has(file)) continue;

      const sql = await fs.readFile(
        path.join(migrationsDir, file),
        "utf8"
      );

      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(
          "INSERT INTO schema_migrations(version) VALUES ($1)",
          [file]
        );
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    }
  });
}

export async function migrateDown() {
  await withClient(async (client) => {
    await ensureMigrationsTable(client);

    const rows = await client.query(
      "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"
    );

    if (rows.rowCount === 0) return;

    const latest = rows.rows[0].version;

    await client.query(
      "DELETE FROM schema_migrations WHERE version = $1",
      [latest]
    );
  });
}

async function main() {
  const direction = process.argv[2] ?? "up";

  if (direction === "down") {
    await migrateDown();
    return;
  }

  await migrateUp();
}

const isDirectCliExecution =
  typeof process.argv[1] === "string" &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectCliExecution) {
  main().catch((error) => {
    console.error("Migration failed", error);
    process.exitCode = 1;
  });
}
