import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/local': {
        target: 'http://localhost:8485',
        timeout: 120000,       // 2 min — LLM calls can be slow
        proxyTimeout: 120000,
      },
      '/api/v1': {
        target: 'http://localhost:8485',
        timeout: 120000,
        proxyTimeout: 120000,
      },
    },
  },
})
