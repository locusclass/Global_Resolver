import { migrateUp } from "../db/migrate.js";

async function main(): Promise<void> {
  await migrateUp();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
