import { migrateUp } from "../db/migrate.js";
async function main() {
    await migrateUp();
}
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
//# sourceMappingURL=seed.js.map