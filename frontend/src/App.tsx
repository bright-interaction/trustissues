import { lazy, Suspense, type ReactNode } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import AuthGuard from '@/components/AuthGuard';
import ErrorBoundary from '@/components/ErrorBoundary';
import { useAuth } from '@/hooks/useAuth';
import Login from '@/pages/Login';
import Setup from '@/pages/Setup';
import Invite from '@/pages/Invite';

// Vault.tsx is provided by the vault module; must default-export the page.
const VaultPage = lazy(() => import('@/pages/Vault'));
const ActivityPage = lazy(() => import('@/pages/Activity'));
const CredentialAccessPage = lazy(() => import('@/pages/CredentialAccess'));
const UsersPage = lazy(() => import('@/pages/Users'));
const SettingsPage = lazy(() => import('@/pages/Settings'));

function PageLoader() {
  return (
    <div className="flex h-screen items-center justify-center">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-slate-300 border-t-slate-600" />
    </div>
  );
}

function VaultOnlyRedirect({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  if (user?.role === 'vault_only') return <Navigate to="/vault" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/setup" element={<Setup />} />
          <Route path="/invite" element={<Invite />} />
          <Route
            path="/"
            element={
              <AuthGuard>
                <Navigate to="/vault" replace />
              </AuthGuard>
            }
          />
          <Route
            path="/vault"
            element={
              <AuthGuard>
                <VaultPage />
              </AuthGuard>
            }
          />
          <Route
            path="/activity"
            element={
              <AuthGuard>
                <VaultOnlyRedirect>
                  <ActivityPage />
                </VaultOnlyRedirect>
              </AuthGuard>
            }
          />
          <Route
            path="/credential-access"
            element={
              <AuthGuard>
                <VaultOnlyRedirect>
                  <CredentialAccessPage />
                </VaultOnlyRedirect>
              </AuthGuard>
            }
          />
          <Route
            path="/users"
            element={
              <AuthGuard>
                <VaultOnlyRedirect>
                  <UsersPage />
                </VaultOnlyRedirect>
              </AuthGuard>
            }
          />
          {/*
            Deliberately NOT wrapped in VaultOnlyRedirect. vault_only is the
            browser-extension role, and Settings holds the only UI that mints an
            extension API key. Redirecting them here meant an invited teammate
            finished onboarding with no key and no way to get one. The server
            already permits their role on POST /api/api-keys, and every
            admin-only surface behind this page is enforced server-side with
            AdminOnly, so the tab list below is presentation, not a boundary.
          */}
          <Route
            path="/settings"
            element={
              <AuthGuard>
                <SettingsPage />
              </AuthGuard>
            }
          />
          <Route path="*" element={<Navigate to="/vault" replace />} />
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
