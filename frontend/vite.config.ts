import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': {
        // Trustissues backend default port (TRUSTISSUES_PORT). Keep in sync
        // with internal/config. See FRONTEND-CONTRACT.md.
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});
