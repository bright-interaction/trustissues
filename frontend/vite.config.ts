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
    // TIMEOUTS ARE SIZED FOR A STARVED RUNNER, NOT FOR A LAPTOP.
    //
    // These suites drive real React through jsdom with userEvent, which is
    // slow by nature: every keystroke is a macrotask and every interaction is
    // wrapped in act(). At vitest's default testTimeout of 5000ms that fits
    // comfortably on an idle machine and does NOT fit on a two-vCPU CI runner
    // executing five test files in parallel. Measured, not guessed: six
    // concurrent `bun run test` invocations on this tree failed 6 out of 6
    // times, always the same two cases, with "Test timed out in 5000ms"
    // followed by a second failure caused by the FIRST one -- an aborted test
    // leaves its component mounted, so the next test renders against a vault
    // that is already unlocked and cannot find its Unlock button. One starved
    // runner therefore produced two failures that look exactly like a lock
    // regression and are not.
    //
    // Raising the ceiling costs nothing in guard strength. A test that asserts
    // a locked vault dropped its secrets asserts the same thing whether it is
    // given 5 seconds or 30; the number only decides how much CPU starvation
    // it tolerates before reporting a bug that is not there. What it must
    // never do is pass -- and that is proven by ablation (revert lockVault's
    // .reset() calls and this suite fails at any timeout), not by the value
    // here.
    testTimeout: 30_000,
    hookTimeout: 30_000,
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
