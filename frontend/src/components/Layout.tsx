import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert } from 'lucide-react';
import Sidebar from './Sidebar';
import { useAuth } from '@/hooks/useAuth';

interface LayoutProps {
  children: ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const { user } = useAuth();

  return (
    <div className="min-h-screen">
      <Sidebar />
      <main className="pl-56">
        {/*
          The vault policy can require 2FA for everyone. Refusing the LOGIN
          would lock out every account the moment an admin ticks the box,
          including accounts that never had a chance to enrol, so login still
          succeeds and the server flags the account here instead.

          This banner is not decoration any more. As of the enrolment gate
          (internal/middleware/totp_enrollment.go) the server refuses every
          route except /api/auth while this flag is set, so a flagged user can
          reach exactly two things: this banner and the enrolment form it links
          to. Every other page will show its own error. Keep the link working
          and keep it pointing at a tab whose data comes only from /api/auth --
          it is the sole way out of the gate.
        */}
        {user?.totp_enrollment_required && (
          <div className="border-b border-amber-200 bg-amber-50 px-6 py-3">
            <div className="mx-auto flex max-w-7xl items-start gap-2.5 text-sm">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
              <p className="text-amber-900">
                <span className="font-medium">
                  Two-factor authentication is required.
                </span>{' '}
                Your administrator requires 2FA on every account. The rest of
                the vault stays locked until you finish setting it up.{' '}
                <Link
                  to="/settings?tab=account"
                  className="font-medium underline hover:text-amber-950"
                >
                  Set it up now
                </Link>
                .
              </p>
            </div>
          </div>
        )}
        <div className="mx-auto max-w-7xl px-6 py-6">{children}</div>
      </main>
    </div>
  );
}
