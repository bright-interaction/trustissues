import { useEffect, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { QRCodeSVG } from 'qrcode.react';
import toast from 'react-hot-toast';
import {
  Check,
  Clock,
  Copy,
  Loader2,
  Mail,
  ShieldCheck,
  User as UserIcon,
} from 'lucide-react';
import Layout from '@/components/Layout';
import { api, ApiError } from '@/lib/api';
import { queryKeys } from '@/lib/query-keys';
import { useAuth } from '@/hooks/useAuth';
import type { SMTPConfig, VaultPolicy } from '@/lib/types';

type SettingsTab = 'account' | 'policy' | 'session' | 'email';

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return 'Something went wrong';
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => toast.error('Could not copy'));
  }
  return (
    <button
      type="button"
      onClick={handleCopy}
      className="text-slate-400 hover:text-slate-900"
      title="Copy"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-600" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </button>
  );
}

const inputClass =
  'w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition-colors focus:border-slate-400 focus:ring-0';
const labelClass = 'mb-1.5 block text-sm font-medium text-slate-700';
const cardClass = 'rounded-xl border border-slate-200 bg-white p-6';
const primaryButtonClass =
  'flex items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-50';

function AccountTab() {
  const { user, refreshUser, logout } = useAuth();
  const [name, setName] = useState(user?.name ?? '');
  const [passwordForm, setPasswordForm] = useState({
    current: '',
    next: '',
    confirm: '',
  });
  const [totpSetupData, setTotpSetupData] = useState<{
    secret: string;
    qr_uri: string;
  } | null>(null);
  const [totpVerifyCode, setTotpVerifyCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disableForm, setDisableForm] = useState({ password: '', code: '' });
  const [showDisable, setShowDisable] = useState(false);

  useEffect(() => {
    setName(user?.name ?? '');
  }, [user?.name]);

  const profileMutation = useMutation({
    mutationFn: () => api.auth.updateProfile({ name }),
    onSuccess: async () => {
      toast.success('Profile updated');
      await refreshUser();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const changePasswordMutation = useMutation({
    mutationFn: () =>
      api.auth.changePassword(passwordForm.current, passwordForm.next),
    onSuccess: () => {
      // The server revokes every session on password change; sign back in.
      toast.success('Password changed. Sign in again with the new one.');
      setPasswordForm({ current: '', next: '', confirm: '' });
      logout();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const totpSetupMutation = useMutation({
    mutationFn: api.auth.totpSetup,
    onSuccess: (data) => setTotpSetupData(data),
    onError: (err) => toast.error(errorMessage(err)),
  });

  const totpVerifyMutation = useMutation({
    mutationFn: (code: string) => api.auth.totpVerify(code),
    onSuccess: async (data) => {
      setTotpSetupData(null);
      setTotpVerifyCode('');
      setRecoveryCodes(data.recovery_codes);
      toast.success('Two-factor authentication enabled');
      await refreshUser();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const totpDisableMutation = useMutation({
    mutationFn: ({ password, code }: { password: string; code: string }) =>
      api.auth.totpDisable(password, code),
    onSuccess: async () => {
      setShowDisable(false);
      setDisableForm({ password: '', code: '' });
      toast.success('Two-factor authentication disabled');
      await refreshUser();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    if (passwordForm.next !== passwordForm.confirm) {
      toast.error('New passwords do not match');
      return;
    }
    if (passwordForm.next.length < 12) {
      toast.error('Password must be at least 12 characters');
      return;
    }
    changePasswordMutation.mutate();
  }

  return (
    <div className="space-y-6">
      <div className={cardClass}>
        <h2 className="mb-4 text-base font-semibold text-slate-900">Profile</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            profileMutation.mutate();
          }}
          className="max-w-sm space-y-4"
        >
          <div>
            <label className={labelClass}>Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>Email</label>
            <input
              type="email"
              value={user?.email ?? ''}
              disabled
              className={`${inputClass} bg-slate-50 text-slate-400`}
            />
          </div>
          <button
            type="submit"
            disabled={profileMutation.isPending}
            className={primaryButtonClass}
          >
            {profileMutation.isPending && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            Save profile
          </button>
        </form>
      </div>

      <div className={cardClass}>
        <h2 className="mb-4 text-base font-semibold text-slate-900">
          Change password
        </h2>
        <form onSubmit={handleChangePassword} className="max-w-sm space-y-4">
          <div>
            <label className={labelClass}>Current password</label>
            <input
              type="password"
              value={passwordForm.current}
              onChange={(e) =>
                setPasswordForm({ ...passwordForm, current: e.target.value })
              }
              required
              autoComplete="current-password"
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>New password</label>
            <input
              type="password"
              value={passwordForm.next}
              onChange={(e) =>
                setPasswordForm({ ...passwordForm, next: e.target.value })
              }
              required
              minLength={12}
              autoComplete="new-password"
              className={inputClass}
              placeholder="Minimum 12 characters"
            />
          </div>
          <div>
            <label className={labelClass}>Confirm new password</label>
            <input
              type="password"
              value={passwordForm.confirm}
              onChange={(e) =>
                setPasswordForm({ ...passwordForm, confirm: e.target.value })
              }
              required
              minLength={12}
              autoComplete="new-password"
              className={inputClass}
            />
          </div>
          <button
            type="submit"
            disabled={changePasswordMutation.isPending}
            className={primaryButtonClass}
          >
            {changePasswordMutation.isPending && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            Change password
          </button>
        </form>
      </div>

      <div className={cardClass}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">
          Two-factor authentication
        </h2>
        <p className="mb-4 text-sm text-slate-500">
          A second factor for the people guarding everyone else's secrets.
        </p>

        {recoveryCodes ? (
          <div className="max-w-md">
            <p className="mb-2 text-sm font-medium text-slate-700">
              Recovery codes. Save them now, they will not be shown again.
            </p>
            <div className="grid grid-cols-2 gap-2 rounded-lg bg-slate-50 p-4 font-mono text-sm text-slate-700">
              {recoveryCodes.map((code) => (
                <span key={code}>{code}</span>
              ))}
            </div>
            <div className="mt-3 flex items-center gap-3">
              <CopyButton text={recoveryCodes.join('\n')} />
              <button
                onClick={() => setRecoveryCodes(null)}
                className="text-sm text-slate-600 hover:text-slate-900"
              >
                I saved them
              </button>
            </div>
          </div>
        ) : totpSetupData ? (
          <div className="max-w-md space-y-4">
            <div className="inline-block rounded-lg border border-slate-200 bg-white p-3">
              <QRCodeSVG value={totpSetupData.qr_uri} size={180} />
            </div>
            <div className="flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 text-xs">
              <span className="flex-1 break-all font-mono text-slate-700">
                {totpSetupData.secret}
              </span>
              <CopyButton text={totpSetupData.secret} />
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                totpVerifyMutation.mutate(totpVerifyCode);
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                inputMode="numeric"
                value={totpVerifyCode}
                onChange={(e) => setTotpVerifyCode(e.target.value)}
                placeholder="000000"
                maxLength={8}
                className={`${inputClass} w-32 tracking-widest`}
              />
              <button
                type="submit"
                disabled={
                  totpVerifyMutation.isPending || totpVerifyCode.length < 6
                }
                className={primaryButtonClass}
              >
                {totpVerifyMutation.isPending && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                )}
                Verify
              </button>
            </form>
          </div>
        ) : user?.totp_enabled ? (
          <div className="max-w-md">
            <p className="mb-3 flex items-center gap-2 text-sm text-emerald-700">
              <ShieldCheck className="h-4 w-4" /> Enabled
            </p>
            {showDisable ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  totpDisableMutation.mutate(disableForm);
                }}
                className="space-y-3"
              >
                <input
                  type="password"
                  value={disableForm.password}
                  onChange={(e) =>
                    setDisableForm({ ...disableForm, password: e.target.value })
                  }
                  required
                  placeholder="Your password"
                  autoComplete="current-password"
                  className={inputClass}
                />
                <input
                  type="text"
                  inputMode="numeric"
                  value={disableForm.code}
                  onChange={(e) =>
                    setDisableForm({ ...disableForm, code: e.target.value })
                  }
                  required
                  placeholder="TOTP or recovery code"
                  className={inputClass}
                />
                <div className="flex items-center gap-2">
                  <button
                    type="submit"
                    disabled={totpDisableMutation.isPending}
                    className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50"
                  >
                    Disable 2FA
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowDisable(false)}
                    className="text-sm text-slate-600 hover:text-slate-900"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <button
                onClick={() => setShowDisable(true)}
                className="text-sm text-slate-600 underline hover:text-slate-900"
              >
                Disable two-factor authentication
              </button>
            )}
          </div>
        ) : (
          <button
            onClick={() => totpSetupMutation.mutate()}
            disabled={totpSetupMutation.isPending}
            className={primaryButtonClass}
          >
            {totpSetupMutation.isPending && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            Enable 2FA
          </button>
        )}
      </div>
    </div>
  );
}

function PolicyTab() {
  const queryClient = useQueryClient();
  const { data: policy, isLoading } = useQuery<VaultPolicy>({
    queryKey: queryKeys.settings.vaultPolicy(),
    queryFn: api.settings.getVaultPolicy,
  });

  const [form, setForm] = useState<VaultPolicy | null>(null);

  useEffect(() => {
    if (policy && !form) setForm(policy);
  }, [policy, form]);

  const saveMutation = useMutation({
    mutationFn: (data: VaultPolicy) => api.settings.updateVaultPolicy(data),
    onSuccess: (saved) => {
      toast.success('Vault policy saved');
      setForm(saved);
      queryClient.setQueryData(queryKeys.settings.vaultPolicy(), saved);
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (isLoading || !form) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className={cardClass}>
      <h2 className="mb-1 text-base font-semibold text-slate-900">
        Vault policy
      </h2>
      <p className="mb-4 text-sm text-slate-500">
        Team-wide rules. Applies to everyone, including you.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          saveMutation.mutate(form);
        }}
        className="max-w-sm space-y-4"
      >
        <div>
          <label className={labelClass}>Minimum password length</label>
          <input
            type="number"
            min={8}
            max={128}
            value={form.min_password_length}
            onChange={(e) =>
              setForm({
                ...form,
                min_password_length: Number(e.target.value),
              })
            }
            className={inputClass}
          />
          <p className="mt-1 text-xs text-slate-400">
            For generated passwords and new account passwords
          </p>
        </div>
        <div>
          <label className={labelClass}>Auto-lock after (minutes)</label>
          <input
            type="number"
            min={1}
            max={480}
            value={form.auto_lock_minutes}
            onChange={(e) =>
              setForm({ ...form, auto_lock_minutes: Number(e.target.value) })
            }
            className={inputClass}
          />
          <p className="mt-1 text-xs text-slate-400">
            The vault relocks itself after this much inactivity
          </p>
        </div>
        <div>
          <label className={labelClass}>Rotation reminder (days)</label>
          <input
            type="number"
            min={0}
            max={3650}
            value={form.rotation_reminder_days}
            onChange={(e) =>
              setForm({
                ...form,
                rotation_reminder_days: Number(e.target.value),
              })
            }
            className={inputClass}
          />
          <p className="mt-1 text-xs text-slate-400">
            Flag entries not rotated within this many days. 0 disables it.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-700">
          <input
            type="checkbox"
            checked={form.require_totp}
            onChange={(e) =>
              setForm({ ...form, require_totp: e.target.checked })
            }
            className="h-4 w-4 rounded border-slate-300"
          />
          Require two-factor authentication for all users
        </label>
        <button
          type="submit"
          disabled={saveMutation.isPending}
          className={primaryButtonClass}
        >
          {saveMutation.isPending && (
            <Loader2 className="h-4 w-4 animate-spin" />
          )}
          Save policy
        </button>
      </form>
    </div>
  );
}

function SessionTab() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: queryKeys.settings.sessionDuration(),
    queryFn: api.settings.getSessionDuration,
  });

  const [hours, setHours] = useState<number | null>(null);

  useEffect(() => {
    if (data && hours === null) setHours(data.duration_hours);
  }, [data, hours]);

  const saveMutation = useMutation({
    mutationFn: (duration_hours: number) =>
      api.settings.updateSessionDuration({ duration_hours }),
    onSuccess: (saved) => {
      toast.success('Session duration saved');
      queryClient.setQueryData(queryKeys.settings.sessionDuration(), saved);
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (isLoading || hours === null) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className={cardClass}>
      <h2 className="mb-1 text-base font-semibold text-slate-900">Sessions</h2>
      <p className="mb-4 text-sm text-slate-500">
        How long a login lasts before the server stops trusting it.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          saveMutation.mutate(hours);
        }}
        className="max-w-sm space-y-4"
      >
        <div>
          <label className={labelClass}>Session duration (hours)</label>
          <input
            type="number"
            min={1}
            max={720}
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className={inputClass}
          />
        </div>
        <button
          type="submit"
          disabled={saveMutation.isPending}
          className={primaryButtonClass}
        >
          {saveMutation.isPending && (
            <Loader2 className="h-4 w-4 animate-spin" />
          )}
          Save
        </button>
      </form>
    </div>
  );
}

function EmailTab() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery<SMTPConfig>({
    queryKey: queryKeys.settings.smtp(),
    queryFn: api.settings.getSMTP,
  });

  const [form, setForm] = useState<
    (SMTPConfig & { password: string }) | null
  >(null);

  useEffect(() => {
    if (data && !form) setForm({ ...data, password: '' });
  }, [data, form]);

  const saveMutation = useMutation({
    mutationFn: (payload: Partial<SMTPConfig & { password?: string }>) =>
      api.settings.updateSMTP(payload),
    onSuccess: (saved) => {
      toast.success('SMTP settings saved');
      setForm({ ...saved, password: '' });
      queryClient.setQueryData(queryKeys.settings.smtp(), saved);
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const testMutation = useMutation({
    mutationFn: api.settings.testSMTP,
    onSuccess: (res) => toast.success(res.message || 'Test email sent'),
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (isLoading || !form) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className={cardClass}>
      <h2 className="mb-1 text-base font-semibold text-slate-900">Email</h2>
      <p className="mb-4 text-sm text-slate-500">
        SMTP for invitation emails and rotation reminders.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const { password, password_set, ...rest } = form;
          void password_set;
          saveMutation.mutate({
            ...rest,
            ...(password ? { password } : {}),
          });
        }}
        className="max-w-sm space-y-4"
      >
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <label className={labelClass}>Host</label>
            <input
              type="text"
              value={form.host}
              onChange={(e) => setForm({ ...form, host: e.target.value })}
              className={inputClass}
              placeholder="smtp.example.com"
            />
          </div>
          <div>
            <label className={labelClass}>Port</label>
            <input
              type="text"
              value={form.port}
              onChange={(e) => setForm({ ...form, port: e.target.value })}
              className={inputClass}
              placeholder="587"
            />
          </div>
        </div>
        <div>
          <label className={labelClass}>From address</label>
          <input
            type="email"
            value={form.from}
            onChange={(e) => setForm({ ...form, from: e.target.value })}
            className={inputClass}
            placeholder="vault@example.com"
          />
        </div>
        <div>
          <label className={labelClass}>Username</label>
          <input
            type="text"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            className={inputClass}
          />
        </div>
        <div>
          <label className={labelClass}>Password</label>
          <input
            type="password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            autoComplete="new-password"
            className={inputClass}
            placeholder={
              form.password_set ? 'Saved. Leave blank to keep it.' : ''
            }
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-700">
          <input
            type="checkbox"
            checked={form.use_tls}
            onChange={(e) => setForm({ ...form, use_tls: e.target.checked })}
            className="h-4 w-4 rounded border-slate-300"
          />
          Use TLS
        </label>
        <div className="flex items-center gap-2">
          <button
            type="submit"
            disabled={saveMutation.isPending}
            className={primaryButtonClass}
          >
            {saveMutation.isPending && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            Save
          </button>
          <button
            type="button"
            onClick={() => testMutation.mutate()}
            disabled={testMutation.isPending}
            className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            {testMutation.isPending && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            Send test email
          </button>
        </div>
      </form>
    </div>
  );
}

export default function Settings() {
  const { isAdmin } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  const tabs: { id: SettingsTab; label: string; icon: typeof UserIcon }[] = [
    { id: 'account', label: 'Account', icon: UserIcon },
    ...(isAdmin
      ? ([
          { id: 'policy', label: 'Vault policy', icon: ShieldCheck },
          { id: 'session', label: 'Sessions', icon: Clock },
          { id: 'email', label: 'Email', icon: Mail },
        ] as const)
      : []),
  ];

  const tabParam = searchParams.get('tab') as SettingsTab | null;
  const activeTab: SettingsTab =
    tabParam && tabs.some((t) => t.id === tabParam) ? tabParam : 'account';

  return (
    <Layout>
      <div className="mb-6">
        <h1
          data-testid="page-settings"
          className="text-xl font-semibold text-slate-900"
        >
          Settings
        </h1>
        <p className="text-sm text-slate-500">
          Your account, and the rules of the vault
        </p>
      </div>

      <div className="mb-6 flex items-center gap-1 border-b border-slate-200">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSearchParams({ tab: tab.id })}
            className={`flex items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-900'
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'account' && <AccountTab />}
      {activeTab === 'policy' && isAdmin && <PolicyTab />}
      {activeTab === 'session' && isAdmin && <SessionTab />}
      {activeTab === 'email' && isAdmin && <EmailTab />}
    </Layout>
  );
}
