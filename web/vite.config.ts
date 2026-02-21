/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import compression from "vite-plugin-compression";
import path from "path";

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    compression({ algorithm: "gzip" }),
    compression({ algorithm: "brotliCompress", ext: ".br" }),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // @ts-expect-error vitest config
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
        manualChunks: {
          vendor: ["react", "react-dom", "react-router-dom"],
          opaque: ["@serenity-kit/opaque"],
        },
      },
    },
  },
});
