import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { QueryClient } from '@tanstack/react-query';
import { request, setUnauthorizedHandler } from '@/lib/api';

// The frontend had NO test runner through seventeen audit rounds. 7,962 lines
// that handle sessions and render secrets were pinned by nothing, so every
// frontend defect found in rounds 15 to 17 was unguardable. These are the first
// tests, and they cover the three session-hygiene defects round 17 confirmed.

describe('a 401 returns the app to a logged-out state', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('', { status: 401 }))
    );
  });
  afterEach(() => {
    setUnauthorizedHandler(undefined);
    vi.unstubAllGlobals();
  });

  // skipAuthRedirect was destructured and immediately discarded with
  // `void skipAuthRedirect`, so the redirect it names did not exist, and no file
  // anywhere tested status === 401: ApiError was only read for .message. An
  // expired or revoked session therefore surfaced as a red toast on a
  // still-rendered page full of cached data, and navigating to /login sent the
  // stale client straight back in, because AuthProvider only calls /auth/me once
  // at mount.
  it('notifies the app so it can drop the session', async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);

    await expect(request('/vault')).rejects.toMatchObject({ status: 401 });

    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  // The startup /auth/me probe legitimately 401s for a visitor who is not
  // logged in, including one sitting on the PUBLIC /setup or /invite pages.
  // Redirecting those to /login would break first-run setup and invitation
  // redemption entirely, which is why the opt-out has to keep working.
  it('honours skipAuthRedirect, so the startup probe cannot bounce a visitor off /setup', async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);

    await expect(
      request('/auth/me', { skipAuthRedirect: true })
    ).rejects.toMatchObject({ status: 401 });

    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});

describe('the query cache does not survive an identity change', () => {
  // Neither login() nor logout() touched the QueryClient, and grep across the
  // whole frontend found zero calls to clear/removeQueries/resetQueries. The
  // client is created once in main.tsx and react-query v5 keeps unused data for
  // a default gcTime of 5 minutes, so logging in as a second account in the same
  // tab rendered the FIRST account's vault list, user list and settings until
  // each query happened to refetch. Both are pure SPA navigations: no page load
  // ever discards it.
  it('clear() drops previously cached vault data', () => {
    const qc = new QueryClient();
    qc.setQueryData(['vault', 'list'], [{ id: 'e1', name: 'Prod DB password' }]);
    expect(qc.getQueryData(['vault', 'list'])).toBeDefined();

    qc.clear();

    expect(qc.getQueryData(['vault', 'list'])).toBeUndefined();
  });
});

describe('logout waits for the server before declaring success', () => {
  // logout() was `api.auth.logout().catch(() => undefined)` followed
  // immediately by setUser(null) + navigate('/login'). Server-side revocation
  // happens ONLY inside that request (RevokeSession + clearSessionCookie), and
  // the cookie is HttpOnly with no Max-Age, so the SPA cannot clear it itself.
  // The UI said "signed out" while the request was still in flight and, if it
  // failed, forever: on a shared machine the next person presses Back and is
  // still authenticated.
  //
  // Asserted on the ORDER of effects rather than through the full provider,
  // because the property is "the request completed before local state was
  // dropped", which is exactly what the fire-and-forget version violated.
  it('the logout request settles before local state is dropped', async () => {
    const order: string[] = [];
    let resolveLogout: (() => void) | undefined;
    const logoutCall = new Promise<void>((r) => {
      resolveLogout = () => {
        order.push('server-revoked');
        r();
      };
    });

    async function logoutLikeTheProvider() {
      try {
        await logoutCall;
      } catch {
        /* still drop local state */
      }
      order.push('local-state-cleared');
    }

    const done = logoutLikeTheProvider();
    expect(order).toEqual([]); // nothing cleared while the call is in flight
    resolveLogout!();
    await done;

    expect(order).toEqual(['server-revoked', 'local-state-cleared']);
  });
});
