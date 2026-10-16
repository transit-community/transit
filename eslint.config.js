// Flat ESLint config for Transit's frontend (TypeScript + React).
// Run: npm run lint

import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

export default [
  {
    files: ["src/**/*.{ts,tsx}", "*.{ts,tsx}"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        ecmaVersion: 2022,
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
    },
    rules: {
      // Hard bans — never land in a non-test file.
      "no-console": "error",
      "no-debugger": "error",
      "no-alert": "error",

      // TS hygiene.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    files: ["**/*.test.{ts,tsx}", "**/tests/**", "**/*.config.{ts,js}", "vite.config.ts"],
    rules: {
      "no-console": "off",
    },
  },
  {
    ignores: ["dist/", "node_modules/", "src-tauri/", "**/*.d.ts", "plans/"],
  },
];
