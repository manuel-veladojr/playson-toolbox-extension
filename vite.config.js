// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // Specify the folder where index.html is located
  root: 'public',
  plugins: [react()],
  build: {
    // Output directory relative to the project root
    outDir: '../dist'
  }
})
