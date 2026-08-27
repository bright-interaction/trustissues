import { CheckCircle2, ExternalLink, KeyRound, ShieldCheck } from 'lucide-react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

const stepClass = 'rounded-lg border border-slate-200 bg-slate-50 p-4';
const actionClass =
  'mt-3 inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100';

// Vault-only accounts are deliberately onboarded in the web app first. The
// invitation proves who may create the account; it does not double as an API
// key. Each link opens in a new tab so this checklist, including the remaining
// security steps, stays visible while the user works through it.
export default function ClientOnboarding() {
  const { user } = useAuth();

  if (user?.role !== 'vault_only') {
    return <Navigate to="/vault" replace />;
  }

  const publicServerUrl = window.location.origin;
  const totpRequired = Boolean(user.totp_enrollment_required);

  return (
    <div className="min-h-screen bg-slate-50 px-6 py-10">
      <main className="mx-auto max-w-2xl rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="mb-6 flex items-start gap-3">
          <div className="rounded-lg bg-emerald-100 p-2">
            <CheckCircle2 className="h-5 w-5 text-emerald-700" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-slate-900">Your account is ready</h1>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">
              Finish these steps in order. Invitation codes are only redeemed in this web app;
              they are never pasted into the browser extension.
            </p>
          </div>
        </div>

        <ol className="space-y-3">
          <li className={stepClass}>
            <div className="flex items-start gap-3">
              <ShieldCheck className="mt-0.5 h-5 w-5 flex-shrink-0 text-slate-600" />
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  1. {totpRequired ? 'Set up two-factor authentication' : 'Check account security'}
                </h2>
                <p className="mt-1 text-sm text-slate-600">
                  {totpRequired
                    ? 'Your administrator requires two-factor authentication. Complete it before opening the vault or creating an API key.'
                    : 'If Trustissues asks for two-factor authentication, complete it before continuing.'}
                </p>
                <a
                  href="/settings?tab=account"
                  target="_blank"
                  rel="noreferrer"
                  className={actionClass}
                >
                  Open account settings <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </div>
            </div>
          </li>

          <li className={stepClass}>
            <h2 className="text-sm font-semibold text-slate-900">
              2. Accept the pending client-vault invitation
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Open Vault and review the pending collection invitation. Its credentials stay
              unavailable until you explicitly accept it.
            </p>
            <a href="/vault" target="_blank" rel="noreferrer" className={actionClass}>
              Open Vault <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </li>

          <li className={stepClass}>
            <div className="flex items-start gap-3">
              <KeyRound className="mt-0.5 h-5 w-5 flex-shrink-0 text-slate-600" />
              <div>
                <h2 className="text-sm font-semibold text-slate-900">
                  3. Create a named extension API key
                </h2>
                <p className="mt-1 text-sm text-slate-600">
                  In Settings, create a key named for this browser or device and copy it when
                  it is shown. Trustissues will not show the full key again.
                </p>
                <a
                  href="/settings?tab=apikeys"
                  target="_blank"
                  rel="noreferrer"
                  className={actionClass}
                >
                  Open API-key settings <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </div>
            </div>
          </li>

          <li className={stepClass}>
            <h2 className="text-sm font-semibold text-slate-900">
              4. Configure the browser extension manually
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Open the extension settings, paste the public server URL and your new API key,
              then save and test the connection. Only add a private URL if the instance
              operator separately supplied one; standard client vaults do not require it.
            </p>
            <label
              htmlFor="public-server-url"
              className="mt-3 block text-xs font-medium uppercase tracking-wide text-slate-500"
            >
              Public server URL
            </label>
            <input
              id="public-server-url"
              readOnly
              value={publicServerUrl}
              onFocus={(event) => event.currentTarget.select()}
              className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-sm text-slate-800"
            />
          </li>
        </ol>

        <p className="mt-5 text-xs leading-relaxed text-slate-500">
          Keep the API key private. If it is exposed, revoke it in Settings and create a new
          named key; invitation codes cannot reconnect an extension.
        </p>
      </main>
    </div>
  );
}
