// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  publicDir: "public", // Static assets including manifest.json go here
  build: {
    outDir: "dist", // Final build output
    emptyOutDir: true,
  },
});
