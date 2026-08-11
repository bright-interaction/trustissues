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
    // Pin a NON-UTC zone. The audit pages take naive SQLite timestamps
    // ("2026-08-10 09:00:00", UTC with no marker) and must append the Z before
    // parsing, or the browser reads them as local and an access at 09:00 UTC
    // displays as 09:00 Stockholm. A guard for that is vacuous in a UTC runner,
    // because both readings agree there: the test would pass on a laptop at
    // +02:00, pass in CI at UTC, and never fail on the machine that has the bug.
    // Freezing the zone makes the two readings differ everywhere the suite runs.
    env: { TZ: 'Europe/Stockholm' },
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
