// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  publicDir: "public", // This is the folder that contains static assets (manifest.json, index.html, etc.)
  build: {
    outDir: "dist", // Build output folder
    emptyOutDir: true,
  },
});
