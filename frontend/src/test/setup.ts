import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Unmount between tests so a component that leaves a secret in the DOM cannot
// make the NEXT test pass by accident. That matters here specifically: several
// of the defects these tests guard are about state surviving longer than it
// should.
afterEach(() => cleanup());
