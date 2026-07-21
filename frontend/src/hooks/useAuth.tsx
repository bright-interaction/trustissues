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
import toast from 'react-hot-toast';
import { api } from '@/lib/api';
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
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const navigate = useNavigate();

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
        setUser(res.user);
        navigate(res.user.role === 'vault_only' ? '/vault' : '/');
      }
      return res;
    },
    [navigate]
  );

  const logout = useCallback(() => {
    // Fire-and-forget: even if the server call fails, drop local state.
    api.auth.logout().catch(() => undefined);
    setUser(null);
    navigate('/login');
  }, [navigate]);

  const refreshUser = useCallback(async () => {
    try {
      const u = await api.auth.me();
      setUser(u);
    } catch {
      // ignore
    }
  }, []);

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
