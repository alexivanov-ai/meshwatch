#!/usr/bin/env node
// electron-builder's NSIS template calls SetDetailsPrint none during install,
// which leaves the detail pane blank even when ShowInstDetails is enabled.
// Patch it once per build so File/extract lines appear in the installer UI.
"use strict";

const fs = require("fs");
const path = require("path");

function findInstallSection(root) {
  const direct = path.join(root, "node_modules", "app-builder-lib", "templates", "nsis", "installSection.nsh");
  if (fs.existsSync(direct)) return direct;
  const libRoot = path.join(root, "node_modules", "app-builder-lib");
  if (!fs.existsSync(libRoot)) return null;
  const stack = [libRoot];
  while (stack.length) {
    const dir = stack.pop();
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) stack.push(p);
      else if (ent.name === "installSection.nsh") return p;
    }
  }
  return null;
}

exports.default = async function patchNsisDetails(context) {
  const root = context.packager.projectDir;
  const file = findInstallSection(root);
  if (!file) {
    throw new Error("installSection.nsh not found — cannot enable installer file details");
  }
  const src = fs.readFileSync(file, "utf8");
  const next = src.replace(/\bSetDetailsPrint none\b/g, "SetDetailsPrint both");
  if (src !== next) fs.writeFileSync(file, next);
};
