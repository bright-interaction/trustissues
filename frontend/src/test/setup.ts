import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterEach } from 'vitest';

// Testing Library's own async budget, which is SEPARATE from vitest's
// testTimeout and much smaller: findBy*/waitFor give up after 1000ms by
// default. That is a full second of wall clock, not of work, so on a CI runner
// running several test files at once it can expire while the render it is
// waiting for is merely descheduled. See the note in vite.config.ts: the same
// contention run that tripped testTimeout also has to clear this one, or the
// suite simply fails a layer further down with "Unable to find an element".
//
// 5000ms is still far below vitest's 30s ceiling, so a genuinely missing
// element fails the assertion long before the test itself is killed, and the
// error says which element rather than "Test timed out".
configure({ asyncUtilTimeout: 5000 });

// Unmount between tests so a component that leaves a secret in the DOM cannot
// make the NEXT test pass by accident. That matters here specifically: several
// of the defects these tests guard are about state surviving longer than it
// should.
afterEach(() => cleanup());
