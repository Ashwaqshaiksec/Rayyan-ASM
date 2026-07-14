import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        // Must target the compose service name 'app', not 'localhost'.
        // Vite runs inside the frontend container; 'localhost' there
        // resolves to the frontend container itself, not the app
        // container, so the backend never received these requests.
        target: 'http://app:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://app:8080',
        ws: true,
      },
    },
  },
  build: {
    outDir: '../dist/frontend',
    emptyOutDir: true,
  },
})
