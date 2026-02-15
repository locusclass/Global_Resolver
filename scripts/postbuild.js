import { mkdirSync, cpSync, existsSync } from "fs";

console.log("🔄 Running postbuild...");

if (!existsSync("dist/db")) {
  mkdirSync("dist/db", { recursive: true });
}

if (existsSync("src/db/migrations")) {
  cpSync("src/db/migrations", "dist/db/migrations", {
    recursive: true,
  });
  console.log("✅ Migrations copied.");
} else {
  console.log("⚠ No migrations folder found.");
}

console.log("🎉 Postbuild complete.");
