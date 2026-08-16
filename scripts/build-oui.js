// Regenerates src/main/oui-data.json from the canonical IEEE MA-L registry.
//
//   node scripts/build-oui.js
//
// Run this occasionally to pick up newly assigned prefixes (TP-Link, for
// example, has shipped under more than one OUI block). Requires internet
// access to standards-oui.ieee.org - the app itself never calls this URL at
// runtime, only this offline build step does.

const https = require("https");
const fs = require("fs");
const path = require("path");

const SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv";
const OUT_FILE = path.join(__dirname, "..", "src", "main", "oui-data.json");

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(fetch(res.headers.location));
      }
      if (res.statusCode !== 200) {
        return reject(new Error("HTTP " + res.statusCode + " fetching " + url));
      }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve(body));
    }).on("error", reject);
  });
}

// Minimal CSV line splitter that understands double-quoted fields
// containing commas - the IEEE feed quotes organization names that have any.
function splitCsvLine(line) {
  const fields = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') { inQuotes = false; }
      else { cur += ch; }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

async function main() {
  console.log("Fetching " + SOURCE_URL + " ...");
  const csv = await fetch(SOURCE_URL);
  const lines = csv.split(/\r?\n/);

  const out = {};
  let count = 0;
  // Columns: Registry,Assignment,Organization Name,Organization Address
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const fields = splitCsvLine(line);
    const registry = fields[0];
    const assignment = (fields[1] || "").trim().toUpperCase();
    const org = (fields[2] || "").trim();
    if (registry !== "MA-L" || !/^[0-9A-F]{6}$/.test(assignment) || !org) continue;
    const prefix = assignment.slice(0, 2) + ":" + assignment.slice(2, 4) + ":" + assignment.slice(4, 6);
    out[prefix] = org;
    count++;
  }

  const sorted = {};
  for (const k of Object.keys(out).sort()) sorted[k] = out[k];

  fs.writeFileSync(OUT_FILE, JSON.stringify(sorted));
  console.log("Wrote " + count + " entries to " + OUT_FILE);
}

main().catch((e) => { console.error(e); process.exit(1); });
