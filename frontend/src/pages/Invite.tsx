import { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { KeyRound, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';

// Public page where an invited colleague redeems an invitation code, sets a
// password, and is logged straight in. Link form: /invite?code=ABC123.
export default function Invite() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login } = useAuth();

  const [code, setCode] = useState(searchParams.get('code') ?? '');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setError('');
    try {
      const res = await api.auth.redeemInvitation(code.trim(), password);
      // Account created; log in with the invite's email + chosen password.
      await login(res.user.email, password);
      navigate(res.user.role === 'vault_only' ? '/vault' : '/', {
        replace: true,
      });
    } catch (err) {
      setError((err as Error).message || 'Could not redeem invitation');
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50">
      <div className="w-full max-w-sm px-6">
        <div className="mb-6 flex items-center justify-center gap-2">
          <KeyRound className="h-6 w-6 text-slate-700" />
          <span className="text-xl font-bold text-slate-900">Trustissues</span>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-6">
          <h1 className="mb-1 text-lg font-semibold text-slate-900">
            Accept your invitation
          </h1>
          <p className="mb-4 text-sm text-slate-500">
            Enter your invitation code and choose a password to create your
            account.
          </p>
          <form onSubmit={onSubmit}>
            <label
              htmlFor="code"
              className="mb-1.5 block text-sm font-medium text-slate-700"
            >
              Invitation code
            </label>
            <input
              id="code"
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              className="mb-4 w-full rounded-lg border border-slate-200 px-3 py-2 text-sm tracking-widest outline-none transition-colors focus:border-slate-400 focus:ring-0"
              placeholder="ABC123"
              autoFocus={!code}
            />
            <label
              htmlFor="password"
              className="mb-1.5 block text-sm font-medium text-slate-700"
            >
              Choose a password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition-colors focus:border-slate-400 focus:ring-0"
              placeholder="At least 12 characters"
              autoFocus={!!code}
            />
            {error && <p className="mt-2 text-xs text-red-500">{error}</p>}
            <button
              type="submit"
              disabled={submitting}
              className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-50"
            >
              {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
              Create account
            </button>
          </form>
          <p className="mt-4 text-center text-xs text-slate-400">
            Already have an account?{' '}
            <Link to="/login" className="text-slate-600 hover:text-slate-900">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
