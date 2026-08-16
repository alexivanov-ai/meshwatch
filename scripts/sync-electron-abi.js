// Keep .npmrc's Electron ABI target aligned with the installed electron
// package. Native modules (better-sqlite3) rebuild against these headers.
// Run automatically from postinstall — no manual Chromium/Electron ABI sync.

const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const electronPkg = path.join(root, "node_modules", "electron", "package.json");
const npmrcPath = path.join(root, ".npmrc");

if (!fs.existsSync(electronPkg)) {
  process.exit(0);
}

const version = require(electronPkg).version;
let npmrc = fs.existsSync(npmrcPath) ? fs.readFileSync(npmrcPath, "utf8") : "";

if (/^target=/m.test(npmrc)) {
  npmrc = npmrc.replace(/^target=.*$/m, "target=" + version);
} else {
  npmrc += (npmrc.endsWith("\n") || !npmrc ? "" : "\n") + "target=" + version + "\n";
}

if (!/^runtime=/m.test(npmrc)) {
  npmrc = "runtime=electron\n" + npmrc;
}
if (!/^disturl=/m.test(npmrc)) {
  npmrc += "disturl=https://electronjs.org/headers\n";
}
if (!/^build_from_source=/m.test(npmrc)) {
  npmrc += "build_from_source=false\n";
}

fs.writeFileSync(npmrcPath, npmrc);
console.log("Synced .npmrc electron ABI target → " + version);
