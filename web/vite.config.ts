import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { compression } from "vite-plugin-compression2";
import path from "path";

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
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
  },
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
      "/.well-known": {
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
        // codeSplitting. Groups match in order — opaque before vendor so the
        // OPAQUE library isn't swallowed by the generic node_modules group.
        codeSplitting: {
          groups: [
            { name: "opaque", test: /@serenity-kit[\\/]opaque/ },
            { name: "vendor", test: /[\\/]node_modules[\\/]/ },
          ],
        },
      },
    },
  },
});
