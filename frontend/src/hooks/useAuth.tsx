import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import {
  api,
  setUnauthorizedHandler,
  setEnrollmentRequiredHandler,
} from '@/lib/api';
import type { User, AuthResponse } from '@/lib/types';

const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const WARNING_BEFORE = 2 * 60 * 1000; // 2 minutes before timeout
const DEBOUNCE_INTERVAL = 30 * 1000; // Only reset timer every 30 seconds

interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  isAdmin: boolean;
  isVaultOnly: boolean;
  setupRequired: boolean;
  login: (
    email: string,
    password: string,
    totpCode?: string
  ) => Promise<AuthResponse>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // A 401 from ANY request drops the session locally.
  //
  // Without this the only auth check was the single /auth/me at mount, so a
  // session revoked or expired mid-visit left the SPA rendering cached data
  // with a red toast, and /login bounced the stale client back into the app.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      queryClient.clear();
      setUser(null);
      navigate('/login');
    });
    return () => setUnauthorizedHandler(undefined);
  }, [navigate, queryClient]);

  useEffect(() => {
    async function init() {
      try {
        // Always check if first-run setup is needed before anything else.
        const status = await api.auth.status();
        if (status.setup_required) {
          setSetupRequired(true);
          setIsLoading(false);
          return;
        }

        // The session is an HttpOnly cookie; the only way to know if it is
        // valid is to ask the server who we are.
        try {
          const u = await api.auth.me();
          setUser(u);
        } catch {
          setUser(null);
        }
      } catch {
        // If status check fails, fall back to normal flow
      } finally {
        setIsLoading(false);
      }
    }

    init();
  }, []);

  const login = useCallback(
    async (
      email: string,
      password: string,
      totpCode?: string
    ): Promise<AuthResponse> => {
      const res = await api.auth.login(email, password, totpCode);
      if (res.totp_required) {
        return res;
      }
      if (res.user) {
        // Clear on the way IN as well as on the way out. A tab that was never
        // logged out (crash, force-quit, a session that simply expired) still
        // holds the previous account's cached data, and login is the point
        // where a different identity takes over the tab.
        queryClient.clear();
        setUser(res.user);
        navigate(res.user.role === 'vault_only' ? '/vault' : '/');
        // Belt and braces behind the login response now carrying
        // totp_enrollment_required. The server is the source of truth for that
        // flag and re-reading it here means a future change to the login
        // payload cannot silently un-render the enrolment banner again.
        void refreshUser();
      }
      return res;
    },
    [navigate]
  );

  const logout = useCallback(async () => {
    // AWAIT the server call, and clear the query cache.
    //
    // This was fire-and-forget: it dropped local state and navigated
    // immediately, so the UI said "signed out" while the request was still in
    // flight and, if it failed, forever. Server-side revocation happens ONLY
    // inside that request (RevokeSession + clearSessionCookie), and the cookie
    // is HttpOnly with no Max-Age, so the SPA cannot clear it itself. On a
    // shared machine that means the next person presses Back and is logged in.
    //
    // The cache matters just as much: React Query held the previous account's
    // vault list, user list and settings with a 5 minute default gcTime, and
    // nothing anywhere called clear/removeQueries/resetQueries. Logging in as a
    // second account in the same tab rendered the FIRST account's data until
    // each query refetched.
    try {
      await api.auth.logout();
    } catch {
      // Still drop local state: a network failure must not strand the user in
      // a session they asked to end. The cookie may survive, which is why the
      // await above exists to make the common case correct.
    }
    queryClient.clear();
    setUser(null);
    navigate('/login');
  }, [navigate, queryClient]);

  const refreshUser = useCallback(async () => {
    try {
      const u = await api.auth.me();
      setUser(u);
    } catch {
      // ignore
    }
  }, []);

  // A 403 from the enrolment gate puts the user where they can actually act.
  //
  // Three separate defects shared one cause: the SPA had no way to learn that
  // the require_totp policy applied to it. /auth/me is read once per page load
  // and refetchOnWindowFocus is off, so a policy switched on mid-session stayed
  // invisible to every open tab until a manual reload; the vault page rendered
  // its refusal as "No secrets stored"; and the gate's machine-readable code was
  // consumed by nothing despite a server-side comment saying otherwise.
  //
  // Routing on the code fixes all three at one point: the tab learns the moment
  // it touches a gated route, refreshUser() makes the banner truthful, and the
  // redirect lands on the only tab that still works -- Settings > Account reads
  // exclusively from /api/auth, which is the group the gate leaves reachable.
  // Settings is deliberately NOT behind VaultOnlyRedirect, so this destination
  // is valid for every role including vault_only.
  const enrollmentRefreshRef = useRef(false);
  useEffect(() => {
    setEnrollmentRequiredHandler(() => {
      // A gated page fires several queries at once and React Query retries each
      // once, so one navigation produces a burst of identical 403s. Collapse the
      // burst into a single /auth/me rather than one per refusal. Navigating to
      // a location already current is a no-op, so it needs no guard of its own.
      if (!enrollmentRefreshRef.current) {
        enrollmentRefreshRef.current = true;
        void refreshUser().finally(() => {
          enrollmentRefreshRef.current = false;
        });
      }
      navigate('/settings?tab=account');
    });
    return () => setEnrollmentRequiredHandler(undefined);
  }, [navigate, refreshUser]);

  // --- Session timeout with auto-logout ---
  const warningTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const logoutTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef<number>(Date.now());
  const warningToastIdRef = useRef<string | null>(null);

  const resetSessionTimer = useCallback(() => {
    if (warningTimeoutRef.current) {
      clearTimeout(warningTimeoutRef.current);
      warningTimeoutRef.current = null;
    }
    if (logoutTimeoutRef.current) {
      clearTimeout(logoutTimeoutRef.current);
      logoutTimeoutRef.current = null;
    }

    if (warningToastIdRef.current) {
      toast.dismiss(warningToastIdRef.current);
      warningToastIdRef.current = null;
    }

    warningTimeoutRef.current = setTimeout(() => {
      warningToastIdRef.current = toast(
        'Session expiring in 2 minutes, click anywhere to stay logged in',
        {
          duration: WARNING_BEFORE,
          icon: '⏳',
        }
      );
    }, SESSION_TIMEOUT - WARNING_BEFORE);

    logoutTimeoutRef.current = setTimeout(() => {
      toast.error('Session expired due to inactivity');
      logout();
    }, SESSION_TIMEOUT);
  }, [logout]);

  useEffect(() => {
    // Only activate the session timer when the user is authenticated
    if (!user) return;

    resetSessionTimer();

    const handleActivity = () => {
      const now = Date.now();
      if (now - lastActivityRef.current >= DEBOUNCE_INTERVAL) {
        lastActivityRef.current = now;
        resetSessionTimer();
      }
    };

    const events: (keyof WindowEventMap)[] = [
      'mousemove',
      'keydown',
      'click',
      'scroll',
    ];

    events.forEach((event) => window.addEventListener(event, handleActivity));

    return () => {
      events.forEach((event) =>
        window.removeEventListener(event, handleActivity)
      );

      if (warningTimeoutRef.current) {
        clearTimeout(warningTimeoutRef.current);
      }
      if (logoutTimeoutRef.current) {
        clearTimeout(logoutTimeoutRef.current);
      }

      if (warningToastIdRef.current) {
        toast.dismiss(warningToastIdRef.current);
      }
    };
  }, [user, resetSessionTimer]);
  // --- End session timeout ---

  const isAdmin = user?.role === 'admin';
  const isVaultOnly = user?.role === 'vault_only';

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAdmin,
        isVaultOnly,
        setupRequired,
        login,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
