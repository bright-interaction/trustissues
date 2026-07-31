import { describe, it, expect } from 'vitest';

describe('the test runner itself', () => {
  it('runs, and jsdom is present', () => {
    expect(typeof document).toBe('object');
    document.body.innerHTML = '<b id="x">ok</b>';
    expect(document.getElementById('x')?.textContent).toBe('ok');
  });
});
