// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  publicDir: "public", // This tells Vite to use the public folder for static assets.
  build: {
    outDir: "dist",  // Output folder for your build files.
  },
});
