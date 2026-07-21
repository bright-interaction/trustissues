import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '@/lib/api';
import { KeyRound, Loader2 } from 'lucide-react';

// First-run page: shown when /api/auth/status reports setup_required (no users
// exist yet). Creates the one and only initial admin account.
export default function Setup() {
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');

    if (password.length < 12) {
      setError('Password must be at least 12 characters');
      return;
    }

    setLoading(true);

    try {
      await api.auth.register(email, password, name);
      // The register response also sets the session cookie; a full reload lets
      // AuthProvider pick up the fresh session state cleanly.
      navigate('/vault');
      window.location.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="mb-3 flex items-center justify-center gap-2">
            <KeyRound className="h-6 w-6 text-slate-700" />
            <span className="text-xl font-bold text-slate-900">
              Trustissues
            </span>
          </div>
          <h1 className="text-lg font-semibold text-slate-900">
            Welcome to Trustissues
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            First run. Create the admin account before someone else does.
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-xl border border-slate-200 bg-white p-6"
        >
          {error && (
            <div className="mb-4 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          )}

          <div className="mb-4">
            <label
              htmlFor="name"
              className="mb-1.5 block text-sm font-medium text-slate-700"
            >
              Your name
            </label>
            <input
              id="name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition-colors focus:border-slate-400 focus:ring-0"
              placeholder="Admin"
            />
          </div>

          <div className="mb-4">
            <label
              htmlFor="email"
              className="mb-1.5 block text-sm font-medium text-slate-700"
            >
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition-colors focus:border-slate-400 focus:ring-0"
              placeholder="admin@example.com"
            />
          </div>

          <div className="mb-6">
            <label
              htmlFor="password"
              className="mb-1.5 block text-sm font-medium text-slate-700"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
              autoComplete="new-password"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition-colors focus:border-slate-400 focus:ring-0"
              placeholder="Minimum 12 characters"
            />
            <p className="mt-1 text-xs text-slate-400">
              This is a password manager. Make it a good one.
            </p>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-50"
          >
            {loading && <Loader2 className="h-4 w-4 animate-spin" />}
            Create admin account
          </button>
        </form>
      </div>
    </div>
  );
}
