// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Ensure publicDir is correctly set (by default it's "public")
  publicDir: 'public'
});
