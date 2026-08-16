// Download Electron's binary if it is missing.
// Used because .npmrc sets ignore-scripts=true (see that file for why), which
// skips electron's own install script during npm ci / npm install.

const fs = require("fs");
const path = require("path");

const electronDir = path.join(__dirname, "..", "node_modules", "electron");
const pathFile = path.join(electronDir, "path.txt");

function hasBinary() {
  if (!fs.existsSync(pathFile)) return false;
  const rel = fs.readFileSync(pathFile, "utf8").trim();
  if (!rel) return false;
  return fs.existsSync(path.join(electronDir, "dist", rel));
}

if (hasBinary()) {
  process.exit(0);
}

const install = path.join(electronDir, "install.js");
if (!fs.existsSync(install)) {
  console.error("electron is not installed. Run npm ci / npm install first.");
  process.exit(1);
}

require(install);
