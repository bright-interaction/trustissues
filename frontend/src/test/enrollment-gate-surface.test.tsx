import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  request,
  setEnrollmentRequiredHandler,
  setUnauthorizedHandler,
  TOTP_ENROLLMENT_REQUIRED_CODE,
} from '@/lib/api';

// The enrolment gate refuses every route except /api/auth while require_totp is
// on and the caller has not enrolled. The server has always sent a
// machine-readable code with that 403, and internal/middleware/totp_enrollment.go
// stated in a comment that "the frontend routes on this string, so it is part of
// the API contract" -- while nothing in this app read `.code` off an ApiError at
// all. A contract asserted on one side and absent on the other is worse than no
// contract, because it stops anyone looking.
//
// The consequence was three separate user-visible defects with one cause: a
// gated user sat on /vault watching every query 403, the page told them their
// secrets did not exist, and an admin flipping the policy mid-session was
// invisible to every open tab until a manual reload.

const jsonResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

afterEach(() => {
  setEnrollmentRequiredHandler(undefined);
  setUnauthorizedHandler(undefined);
  vi.unstubAllGlobals();
});

describe('the enrolment gate 403 reaches the app', () => {
  it('notifies the app, so the tab can learn the policy applies to it', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(403, {
          error: 'two-factor authentication is required',
          code: TOTP_ENROLLMENT_REQUIRED_CODE,
        })
      )
    );
    const onEnrollmentRequired = vi.fn();
    setEnrollmentRequiredHandler(onEnrollmentRequired);

    await expect(request('/vault')).rejects.toMatchObject({ status: 403 });

    expect(onEnrollmentRequired).toHaveBeenCalledTimes(1);
  });

  // The code is what distinguishes the gate from every other refusal. Routing an
  // ordinary 403 to the enrolment page would drag users off whatever they were
  // doing whenever a permission check failed -- an authorization error is not an
  // enrolment error and must not navigate.
  it('ignores a 403 that is not the gate, so an authz refusal does not hijack navigation', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(403, { error: 'incorrect password' }))
    );
    const onEnrollmentRequired = vi.fn();
    setEnrollmentRequiredHandler(onEnrollmentRequired);

    await expect(request('/vault/unlock')).rejects.toMatchObject({ status: 403 });

    expect(onEnrollmentRequired).not.toHaveBeenCalled();
  });

  // A 403 carrying a DIFFERENT code must not match either. The check has to be
  // on the code's value, not on the mere presence of a code field.
  it('ignores a 403 carrying some other code', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(403, { error: 'nope', code: 'some_other_reason' })
      )
    );
    const onEnrollmentRequired = vi.fn();
    setEnrollmentRequiredHandler(onEnrollmentRequired);

    await expect(request('/vault')).rejects.toMatchObject({ status: 403 });

    expect(onEnrollmentRequired).not.toHaveBeenCalled();
  });

  // The two interceptors must not be crossed. A dead session and an un-enrolled
  // account need opposite responses: one logs you out, the other must NOT,
  // because being sent to /login would strand a user whose session is perfectly
  // valid and whose only problem is that they have not set up 2FA yet.
  it('does not fire on a 401, and the 401 handler does not fire on the gate', async () => {
    const onEnrollmentRequired = vi.fn();
    const onUnauthorized = vi.fn();
    setEnrollmentRequiredHandler(onEnrollmentRequired);
    setUnauthorizedHandler(onUnauthorized);

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('', { status: 401 }))
    );
    await expect(request('/vault')).rejects.toMatchObject({ status: 401 });
    expect(onEnrollmentRequired).not.toHaveBeenCalled();
    expect(onUnauthorized).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
    onUnauthorized.mockClear();

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(403, {
          error: 'two-factor authentication is required',
          code: TOTP_ENROLLMENT_REQUIRED_CODE,
        })
      )
    );
    await expect(request('/vault')).rejects.toMatchObject({ status: 403 });
    expect(onEnrollmentRequired).toHaveBeenCalledTimes(1);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  // The refusal must still reach the caller as an error. If the interceptor
  // swallowed it, every caller's own error handling would go dead and the page
  // would render its empty state again -- the exact defect being fixed.
  it('still throws, so callers can render a refusal rather than an empty state', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(403, {
          error: 'two-factor authentication is required',
          code: TOTP_ENROLLMENT_REQUIRED_CODE,
        })
      )
    );
    setEnrollmentRequiredHandler(vi.fn());

    await expect(request('/vault')).rejects.toMatchObject({
      status: 403,
      body: { code: TOTP_ENROLLMENT_REQUIRED_CODE },
    });
  });
});

// The client's constant must equal the server's, or the interceptor above is
// dead code that no test would notice: every assertion here uses the client
// constant on both sides, so a drift would stay green.
describe('the code is the same string on both sides of the contract', () => {
  it('matches middleware.TOTPEnrollmentRequiredCode in the Go source', async () => {
    const fs = await import('fs');
    const path = await import('path');
    // vitest runs with cwd = frontend/, so the Go source is one level up.
    const goPath = path.resolve(
      process.cwd(),
      '../internal/middleware/totp_enrollment.go'
    );
    expect(
      fs.existsSync(goPath),
      `the Go source was not found at ${goPath}; this guard is looking in the wrong place and would pass against any drift`
    ).toBe(true);
    const go = fs.readFileSync(goPath, 'utf8');
    const m = go.match(/TOTPEnrollmentRequiredCode\s*=\s*"([^"]+)"/);
    expect(m, 'the Go constant could not be found; this guard is looking in the wrong place').not.toBeNull();
    expect(m![1]).toBe(TOTP_ENROLLMENT_REQUIRED_CODE);
  });
});
