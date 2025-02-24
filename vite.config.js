// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // Instead of root, use publicDir to define static assets location
  publicDir: 'public',
  plugins: [react()],
  build: {
    outDir: 'dist'
  }
})
