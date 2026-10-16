import path from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],

  resolve: {
    alias: {
      // `import.meta.dirname` rather than `__dirname`: Vite 8.2 warns that
      // `__dirname` is unsupported by the `configLoader: 'native'` mode that
      // is slated to become the default in a future major. Needs Node 20.11+;
      // our floor is 22.
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },

  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },

  test: {
    environment: "happy-dom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    // Vitest's default exclude covers node_modules/dist, NOT nested git
    // worktrees. A `.claude/worktrees/<name>` checkout duplicates every
    // test file, and its copies resolve `@/` against THIS tree's src
    // (the alias above is absolute) while relative imports hit the
    // stale copy — a mixed-version suite that fails on any real change.
    exclude: ["**/node_modules/**", "**/dist/**", "**/.claude/worktrees/**", "**/*.worktrees/**"],
  },
});
