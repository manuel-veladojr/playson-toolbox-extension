// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // Root is now the project root
  root: './',
  // Specify public directory for static assets
  publicDir: 'public',
  plugins: [react()],
  build: {
    outDir: 'dist'
  }
})
