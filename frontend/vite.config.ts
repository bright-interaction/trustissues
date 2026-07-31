/// <reference types="vitest" />
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
  // The frontend had NO test runner through seventeen audit rounds: package.json
  // scripts were exactly dev/build/preview, and 7,962 lines of code that handles
  // sessions and renders secrets was pinned by nothing. Every frontend defect
  // found in rounds 15 to 17 was therefore unguardable.
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
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
