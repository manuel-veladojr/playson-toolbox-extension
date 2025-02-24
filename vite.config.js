// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Tell Vite where to find static files
  publicDir: 'public',
  build: {
    // Specify the output directory
    outDir: 'dist'
  }
});
