// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  root: "public", // Set the root to the public folder
  build: {
    outDir: "../dist", // Build output folder
    emptyOutDir: true,
  },
});
