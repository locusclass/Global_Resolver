import fs from "fs";
import path from "path";

const root = process.cwd();
const packageJsonPath = path.join(root, "package.json");
const scriptsDir = path.join(root, "scripts");
const postbuildPath = path.join(scriptsDir, "postbuild.js");

console.log("🔧 Fixing build configuration...");

// ---- 1️⃣ Ensure package.json exists ----
if (!fs.existsSync(packageJsonPath)) {
  console.error("❌ package.json not found.");
  process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));

// ---- 2️⃣ Replace build script ----
if (!pkg.scripts) pkg.scripts = {};

pkg.scripts.build =
  "node ./node_modules/typescript/bin/tsc -p tsconfig.build.json && node scripts/postbuild.js";

console.log("✅ Updated build script.");

// ---- 3️⃣ Ensure scripts directory exists ----
if (!fs.existsSync(scriptsDir)) {
  fs.mkdirSync(scriptsDir);
  console.log("📁 Created scripts directory.");
}

// ---- 4️⃣ Create postbuild.js ----
const postbuildContent = `import { mkdirSync, cpSync, existsSync } from "fs";

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
`;

fs.writeFileSync(postbuildPath, postbuildContent);

console.log("✅ Created scripts/postbuild.js");

// ---- 5️⃣ Save updated package.json ----
fs.writeFileSync(packageJsonPath, JSON.stringify(pkg, null, 2));

console.log("🎉 Build system successfully fixed.");
console.log("Now run: npm run build");
