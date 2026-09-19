import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { compression } from "vite-plugin-compression2";
import path from "path";

// vitest reads this config too, but under pnpm isolation its UserConfig
// augmentation binds to its own vite (peer ^6||^7) rather than our vite 8 —
// so the `test` field is spread in (spreads bypass excess-property checks)
// instead of relying on module augmentation or @ts-expect-error.
const test = {
  globals: true,
  environment: "node",
  include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
};

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    // Precompressed assets (.gz + .br, zlib level 9 / brotli 11 by default).
    // skipIfLargerOrEqual (the default) omits compressed copies that wouldn't
    // shrink — every emitted artifact stays smaller than its original.
    compression({ algorithms: ["gzip", "brotliCompress"] }),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  ...({ test } as object),
  server: {
    port: 5378,
    strictPort: true,
    proxy: {
      "/v1": {
        target: "http://localhost:5377",
        changeOrigin: true,
      },
      "/oauth": {
        target: "http://localhost:5377",
        changeOrigin: true,
      },
      "/health": {
        target: "http://localhost:5377",
        changeOrigin: true,
      },
      // CAP proof-of-work assets and API (served by CAP container in dev)
      "/cap": {
        target: process.env.VITE_CAP_URL || "http://localhost:3000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/cap/, ""),
      },
    },
  },
  build: {
    outDir: "dist",
    target: "es2022",
    rollupOptions: {
      output: {
        // vite 8 bundles with rolldown, which replaces manualChunks with
        // advancedChunks. Groups match in order — opaque before vendor so the
        // OPAQUE library isn't swallowed by the generic node_modules group.
        advancedChunks: {
          groups: [
            { name: "opaque", test: /@serenity-kit[\\/]opaque/ },
            { name: "vendor", test: /[\\/]node_modules[\\/]/ },
          ],
        },
      },
    },
  },
});
