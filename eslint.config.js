// ESLint flat config (ESLint 9+). No build step, no bundler — this just
// points ESLint at each part of the app with the right runtime globals:
// Node for the main process/preload/scripts, browser for the renderer.
// Run: npx eslint .
"use strict";

const js = require("@eslint/js");
const globals = require("globals");

module.exports = [
  js.configs.recommended,

  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "build/**",
      "src/renderer/vendor/**",
      "src/main/oui-data.json"
    ]
  },

  // Main process, preload bridge, build/dev scripts, and this config file
  // itself — plain CommonJS with full Node globals.
  {
    files: ["src/main/**/*.js", "src/preload.js", "scripts/**/*.js", "eslint.config.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { ...globals.node }
    }
  },

  // Renderer — loaded via a plain <script> tag (no bundler, no ESM), so
  // top-level `var`/`function` are real globals shared across app.js; only
  // window.meshwatch (the preload bridge) reaches into the main process.
  {
    files: ["src/renderer/**/*.js"],
    ignores: ["src/renderer/vendor/**"],
    languageOptions: {
      sourceType: "script",
      globals: { ...globals.browser }
    }
  },

  {
    rules: {
      // caughtErrors: "none" matches this codebase's consistent
      // catch (e) { /* ignore */ } convention — a deliberate, widely used
      // style here, not an oversight, so it shouldn't warn on every one.
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" }]
    }
  }
];
