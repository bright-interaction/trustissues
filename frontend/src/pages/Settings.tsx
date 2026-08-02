import { useEffect, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { QRCodeSVG } from 'qrcode.react';
import toast from 'react-hot-toast';
import {
  AlertTriangle,
  Bell,
  Bot,
  Check,
  Clock,
  Copy,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  Send,
  ShieldCheck,
  Trash2,
  User as UserIcon,
} from 'lucide-react';
import Layout from '@/components/Layout';
import { api, ApiError } from '@/lib/api';
import { vaultApi } from '@/lib/vault-types';
import { queryKeys } from '@/lib/query-keys';
import { useAuth } from '@/hooks/useAuth';
import type {
  SMTPConfig,
  VaultPolicy,
  ApiKeyCreated,
  AIConfig,
  VaultKeyStatus,
} from '@/lib/types';
import { NOTIFICATION_EVENTS, type NotificationEvent } from '@/lib/types';

type SettingsTab =
  | 'account'
  | 'policy'
  | 'session'
  | 'email'
  | 'channels'
  | 'apikeys'
  | 'encryption'
  | 'ai';

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
  // Enabling 2FA requires the account password: see api.auth.totpVerify.
  const [totpEnablePassword, setTotpEnablePassword] = useState('');
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
    mutationFn: ({ code, password }: { code: string; password: string }) =>
      api.auth.totpVerify(code, password),
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
                totpVerifyMutation.mutate({
                  code: totpVerifyCode,
                  password: totpEnablePassword,
                });
              }}
              className="flex flex-col gap-2 sm:flex-row sm:items-center"
            >
              <input
                type="password"
                autoComplete="current-password"
                placeholder="Your password"
                value={totpEnablePassword}
                onChange={(e) => setTotpEnablePassword(e.target.value)}
                required
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm sm:w-44"
              />
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
                  // NOT inputMode="numeric": this field accepts a recovery code too,
                  // and those are hex (see totp.GenerateRecoveryCodes). A numeric
                  // keypad made the documented recovery path awkward to actually use
                  // on a phone, which is the device you reach for when your
                  // authenticator is gone.
                  autoComplete="one-time-code"
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
            value={form.auto_lock_max_minutes}
            onChange={(e) =>
              setForm({ ...form, auto_lock_max_minutes: Number(e.target.value) })
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
  const [idle, setIdle] = useState<number | null>(null);

  useEffect(() => {
    if (data && hours === null) setHours(data.duration_hours);
    if (data && idle === null) setIdle(data.idle_minutes);
  }, [data, hours, idle]);

  const saveMutation = useMutation({
    mutationFn: (payload: { duration_hours: number; idle_minutes: number }) =>
      api.settings.updateSessionDuration(payload),
    onSuccess: (saved) => {
      toast.success('Session duration saved');
      queryClient.setQueryData(queryKeys.settings.sessionDuration(), saved);
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (isLoading || hours === null || idle === null) {
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
          saveMutation.mutate({ duration_hours: hours, idle_minutes: idle });
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
          <p className="mt-1 text-xs text-slate-500">
            Absolute lifetime. A session is dropped this long after sign-in even
            if it is in constant use.
          </p>
        </div>
        <div>
          <label className={labelClass}>Idle timeout (minutes)</label>
          <input
            type="number"
            min={1}
            max={1440}
            value={idle}
            onChange={(e) => setIdle(Number(e.target.value))}
            className={inputClass}
          />
          <p className="mt-1 text-xs text-slate-500">
            How long an unused session survives. Separate from the vault
            auto-lock, which only decides how long a decrypted vault stays open
            in the browser.
          </p>
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

  // "Send test email" tests the STORED config, never what is on screen.
  //
  // POST /api/settings/smtp/test reads nothing from the request body: the
  // handler sends using the values already persisted in the settings table. The
  // button sits inside the same form as the host/port/password inputs, right
  // next to Save, so an operator who edits the host and presses Test is told
  // "Test email sent" about the OLD host, and concludes the new one works. The
  // reverse is worse: they fix a broken host, press Test, see it fail, and
  // conclude the fix did not work.
  const smtpDirty =
    !!form && !!data &&
    (form.host !== data.host ||
      form.port !== data.port ||
      form.from !== data.from ||
      form.username !== data.username ||
      form.use_tls !== data.use_tls ||
      form.password !== '');

  const testMutation = useMutation({
    mutationFn: api.settings.testSMTP,
    onSuccess: (res) =>
      toast.success(
        (res.message || 'Test email sent') + ' (using the saved settings)'
      ),
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
            disabled={testMutation.isPending || smtpDirty}
            title={
              smtpDirty
                ? 'Save first: the test sends with the stored settings, not the edits on screen'
                : undefined
            }
            className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            {testMutation.isPending && (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
            Send test email
          </button>
          {smtpDirty && (
            <p className="self-center text-xs text-amber-600">
              Save your changes first. The test uses the stored settings.
            </p>
          )}
        </div>
      </form>
    </div>
  );
}

// Human labels for the wire event names. Kept next to the tab so the union in
// types.ts stays the single source of truth for what the server accepts.
const EVENT_LABELS: Record<NotificationEvent, string> = {
  'vault.rotation_failed': 'Rotation failed',
  'vault.rotation_partial': 'Rotation did not fully deliver',
  'vault.secret_expiring': 'Secret expiring soon',
};

const EVENT_HINTS: Record<NotificationEvent, string> = {
  'vault.rotation_failed':
    'An automatic rotation could not complete. The stored secret was left untouched.',
  'vault.rotation_partial':
    'The new value was stored but at least one delivery target did not accept it.',
  'vault.secret_expiring':
    'A secret is approaching its expiry date and needs attention.',
};

function ChannelsTab() {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [type, setType] = useState<'webhook' | 'slog'>('webhook');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [events, setEvents] = useState<NotificationEvent[]>([
    ...NOTIFICATION_EVENTS,
  ]);

  const channelsQuery = useQuery({
    queryKey: queryKeys.admin.notificationChannels(),
    queryFn: () => api.admin.listNotificationChannels(),
  });

  const invalidate = () =>
    queryClient.invalidateQueries({
      queryKey: queryKeys.admin.notificationChannels(),
    });

  const createMutation = useMutation({
    mutationFn: () =>
      api.admin.createNotificationChannel({
        name: name.trim(),
        type,
        config: type === 'webhook' ? { url: url.trim(), secret: secret.trim() || undefined } : undefined,
        events,
      }),
    onSuccess: () => {
      toast.success('Channel created');
      setName('');
      setUrl('');
      setSecret('');
      setEvents([...NOTIFICATION_EVENTS]);
      invalidate();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.admin.setNotificationChannelEnabled(id, enabled),
    onSuccess: (_data, vars) => {
      toast.success(vars.enabled ? 'Channel enabled' : 'Channel disabled');
      invalidate();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => api.admin.testNotificationChannel(id),
    onSuccess: () => toast.success('Test notification sent'),
    onError: (err) => toast.error(errorMessage(err)),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.admin.deleteNotificationChannel(id),
    onSuccess: () => {
      toast.success('Channel deleted');
      invalidate();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const channels = channelsQuery.data ?? [];
  const enabledCount = channels.filter((c) => c.enabled).length;
  const canSubmit =
    name.trim() !== '' &&
    events.length > 0 &&
    (type !== 'webhook' || url.trim() !== '');

  const toggleEvent = (e: NotificationEvent) =>
    setEvents((prev) =>
      prev.includes(e) ? prev.filter((x) => x !== e) : [...prev, e]
    );

  return (
    <div className="max-w-2xl space-y-6">
      {/*
        The whole point of this tab. Every alert the product can raise fans out
        to enabled channels, so with none configured expiry reminders and
        rotation alerts are silently discarded. Say so plainly rather than
        showing an innocuous empty list.
      */}
      {!channelsQuery.isLoading && enabledCount === 0 && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
          <div className="text-sm">
            <p className="font-medium text-amber-900">
              No alerts are being delivered
            </p>
            <p className="mt-0.5 text-amber-800">
              {channels.length === 0
                ? 'There are no notification channels, so rotation failures and expiry reminders are only written to the server log.'
                : 'Every channel is disabled, so rotation failures and expiry reminders are only written to the server log.'}{' '}
              Add a channel below to start receiving them.
            </p>
          </div>
        </div>
      )}

      <div className={cardClass}>
        <h2 className="text-sm font-semibold text-slate-900">
          Add a notification channel
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Channels are where Trustissues sends alerts about your secrets. A
          webhook posts a signed JSON payload to a URL you control; the server
          log channel writes to this server's own log, which is useful for a
          quick check that alerting works at all.
        </p>

        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (canSubmit) createMutation.mutate();
          }}
          className="mt-4 space-y-4"
        >
          <div>
            <label className={labelClass} htmlFor="channel-name">
              Name
            </label>
            <input
              id="channel-name"
              className={inputClass}
              placeholder="e.g. Ops Slack"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div>
            <label className={labelClass} htmlFor="channel-type">
              Type
            </label>
            <select
              id="channel-type"
              className={inputClass}
              value={type}
              onChange={(e) => setType(e.target.value as 'webhook' | 'slog')}
            >
              <option value="webhook">Webhook</option>
              <option value="slog">Server log</option>
            </select>
          </div>

          {type === 'webhook' && (
            <>
              <div>
                <label className={labelClass} htmlFor="channel-url">
                  Webhook URL
                </label>
                <input
                  id="channel-url"
                  className={inputClass}
                  placeholder="https://hooks.example.com/services/..."
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <div>
                <label className={labelClass} htmlFor="channel-secret">
                  Signing secret{' '}
                  <span className="font-normal text-slate-400">(optional)</span>
                </label>
                <input
                  id="channel-secret"
                  type="password"
                  className={inputClass}
                  placeholder="Used to HMAC-sign each payload"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                />
                <p className="mt-1.5 text-xs text-slate-500">
                  Stored encrypted and never shown again. To change the URL or
                  secret later, delete this channel and create a new one.
                </p>
              </div>
            </>
          )}

          <div>
            <span className={labelClass}>Send on</span>
            <div className="space-y-2">
              {NOTIFICATION_EVENTS.map((e) => (
                <label
                  key={e}
                  className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-slate-200 p-3 transition-colors hover:border-slate-300"
                >
                  <input
                    type="checkbox"
                    className="mt-0.5 h-4 w-4 rounded border-slate-300"
                    checked={events.includes(e)}
                    onChange={() => toggleEvent(e)}
                  />
                  <span className="text-sm">
                    <span className="font-medium text-slate-800">
                      {EVENT_LABELS[e]}
                    </span>
                    <span className="mt-0.5 block text-xs text-slate-500">
                      {EVENT_HINTS[e]}
                    </span>
                  </span>
                </label>
              ))}
            </div>
            {events.length === 0 && (
              <p className="mt-1.5 text-xs text-amber-600">
                Pick at least one event, or this channel will never fire.
              </p>
            )}
          </div>

          <button
            type="submit"
            className={primaryButtonClass}
            disabled={!canSubmit || createMutation.isPending}
          >
            {createMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Bell className="h-4 w-4" />
            )}
            Add channel
          </button>
        </form>
      </div>

      <div className={cardClass}>
        <h2 className="text-sm font-semibold text-slate-900">Channels</h2>
        {channelsQuery.isLoading ? (
          <div className="mt-4 flex justify-center">
            <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
          </div>
        ) : channels.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">
            No channels yet. Add one above to start receiving alerts.
          </p>
        ) : (
          <ul className="mt-3 divide-y divide-slate-100">
            {channels.map((c) => (
              <li key={c.id} className="py-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-medium text-slate-800">
                        {c.name}
                      </span>
                      <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600">
                        {c.type === 'slog' ? 'server log' : c.type}
                      </span>
                      {!c.enabled && (
                        <span className="rounded-md bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-500">
                          disabled
                        </span>
                      )}
                    </div>
                    <p className="mt-1 truncate text-xs text-slate-500">
                      {c.events
                        .split(',')
                        .map(
                          (e) =>
                            EVENT_LABELS[e.trim() as NotificationEvent] ??
                            e.trim()
                        )
                        .join(', ')}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      onClick={() => testMutation.mutate(c.id)}
                      disabled={testMutation.isPending}
                      title="Send a test notification"
                      className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-slate-50 hover:text-slate-700 disabled:opacity-50"
                    >
                      <Send className="h-4 w-4" />
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        toggleMutation.mutate({ id: c.id, enabled: !c.enabled })
                      }
                      disabled={toggleMutation.isPending}
                      className="rounded-lg px-2.5 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 disabled:opacity-50"
                    >
                      {c.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (
                          window.confirm(
                            `Delete the channel "${c.name}"? Alerts will stop going to it immediately.`
                          )
                        ) {
                          deleteMutation.mutate(c.id);
                        }
                      }}
                      disabled={deleteMutation.isPending}
                      title="Delete channel"
                      className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-red-50 hover:text-red-600 disabled:opacity-50"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function ApiKeysTab() {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);

  const keysQuery = useQuery({
    queryKey: queryKeys.apiKeys.list(),
    queryFn: () => api.apiKeys.list(),
  });

  const createMutation = useMutation({
    mutationFn: () => api.apiKeys.create({ name: name.trim() }),
    onSuccess: (key) => {
      setCreated(key);
      setName('');
      queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys.all });
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.apiKeys.delete(id),
    onSuccess: () => {
      toast.success('API key revoked');
      queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys.all });
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const keys = keysQuery.data ?? [];

  return (
    <div className="max-w-2xl space-y-6">
      <div className={cardClass}>
        <h2 className="text-sm font-semibold text-slate-900">
          Browser extension and API access
        </h2>
        <p className="mt-1 text-sm text-slate-500">
          Create a key to connect the Trustissues browser extension or any
          programmatic client. In the extension settings, enter this server's
          address and paste the key. The key is shown once, so copy it now.
        </p>

        <form
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (name.trim()) createMutation.mutate();
          }}
          className="mt-4 flex items-end gap-3"
        >
          <div className="flex-1">
            <label className={labelClass} htmlFor="apikey-name">
              Key name
            </label>
            <input
              id="apikey-name"
              className={inputClass}
              placeholder="e.g. My laptop extension"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <button
            type="submit"
            className={primaryButtonClass}
            disabled={!name.trim() || createMutation.isPending}
          >
            {createMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <KeyRound className="h-4 w-4" />
            )}
            Create key
          </button>
        </form>

        {created && (
          <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-4">
            <p className="text-sm font-medium text-amber-900">
              Copy your new key now. You will not see it again.
            </p>
            <div className="mt-2 flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded-md bg-white px-3 py-2 font-mono text-xs text-slate-800">
                {created.key}
              </code>
              <CopyButton text={created.key} />
            </div>
            <button
              type="button"
              onClick={() => setCreated(null)}
              className="mt-3 text-xs font-medium text-amber-800 hover:text-amber-950"
            >
              I have copied it, dismiss
            </button>
          </div>
        )}
      </div>

      <div className={cardClass}>
        <h2 className="text-sm font-semibold text-slate-900">Your API keys</h2>
        {keysQuery.isLoading ? (
          <div className="mt-4 flex justify-center">
            <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
          </div>
        ) : keys.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No API keys yet.</p>
        ) : (
          <ul className="mt-3 divide-y divide-slate-100">
            {keys.map((k) => (
              <li
                key={k.id}
                className="flex items-center justify-between py-3"
              >
                <div>
                  <p className="text-sm font-medium text-slate-900">{k.name}</p>
                  <p className="font-mono text-xs text-slate-400">
                    ti_{k.key_prefix}...
                    {k.last_used_at
                      ? ` last used ${new Date(k.last_used_at).toLocaleDateString()}`
                      : ' never used'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => deleteMutation.mutate(k.id)}
                  disabled={deleteMutation.isPending}
                  className="text-slate-400 transition-colors hover:text-red-600"
                  title="Revoke key"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function StatusPill({
  on,
  onLabel,
  offLabel,
}: {
  on: boolean;
  onLabel: string;
  offLabel: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${
        on ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-500'
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          on ? 'bg-emerald-500' : 'bg-slate-400'
        }`}
      />
      {on ? onLabel : offLabel}
    </span>
  );
}

function CodeBox({ value }: { value: string }) {
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 overflow-x-auto rounded-md bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800">
        {value}
      </code>
      <CopyButton text={value} />
    </div>
  );
}

function AITab() {
  const { isAdmin } = useAuth();
  const queryClient = useQueryClient();

  const { data: config, isLoading } = useQuery<AIConfig>({
    queryKey: queryKeys.ai.config(),
    queryFn: api.ai.getConfig,
  });

  // The vault list backs the provider-key dropdowns. Only admins can change the
  // keys, so only they need the list.
  const vaultQuery = useQuery({
    queryKey: queryKeys.vault.list(),
    queryFn: () => vaultApi.list(),
    enabled: isAdmin,
  });

  const [form, setForm] = useState<{
    anthropic_entry_id: string;
    openai_entry_id: string;
  } | null>(null);

  useEffect(() => {
    if (config && !form) {
      setForm({
        anthropic_entry_id: config.anthropic_entry_id,
        openai_entry_id: config.openai_entry_id,
      });
    }
  }, [config, form]);

  const saveMutation = useMutation({
    mutationFn: (data: {
      anthropic_entry_id?: string | null;
      openai_entry_id?: string | null;
    }) => api.ai.updateConfig(data),
    onSuccess: (saved) => {
      toast.success('Provider keys saved');
      queryClient.setQueryData(queryKeys.ai.config(), saved);
      setForm({
        anthropic_entry_id: saved.anthropic_entry_id,
        openai_entry_id: saved.openai_entry_id,
      });
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (isLoading || !config || (isAdmin && (!form || vaultQuery.isLoading))) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
      </div>
    );
  }

  const apiKeyEntries = (vaultQuery.data ?? []).filter(
    (entry) => entry.category === 'api_key'
  );

  return (
    <div className="max-w-2xl space-y-6">
      <div className={cardClass}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">
          Provider keys
        </h2>
        <p className="mb-4 text-sm text-slate-500">
          The team key each provider uses. It stays in the vault and is injected
          server-side, so no one pastes a raw key into an AI client.
        </p>

        {isAdmin && form ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              saveMutation.mutate({
                anthropic_entry_id: form.anthropic_entry_id,
                openai_entry_id: form.openai_entry_id,
              });
            }}
            className="space-y-4"
          >
            <div>
              <div className="mb-1.5 flex items-center gap-2">
                <label className="text-sm font-medium text-slate-700">
                  Anthropic
                </label>
                <StatusPill
                  on={config.anthropic_configured}
                  onLabel="Configured"
                  offLabel="Not set"
                />
              </div>
              <select
                className={inputClass}
                value={form.anthropic_entry_id}
                onChange={(e) =>
                  setForm({ ...form, anthropic_entry_id: e.target.value })
                }
              >
                <option value="">Not configured</option>
                {apiKeyEntries.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {entry.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <div className="mb-1.5 flex items-center gap-2">
                <label className="text-sm font-medium text-slate-700">
                  OpenAI
                </label>
                <StatusPill
                  on={config.openai_configured}
                  onLabel="Configured"
                  offLabel="Not set"
                />
              </div>
              <select
                className={inputClass}
                value={form.openai_entry_id}
                onChange={(e) =>
                  setForm({ ...form, openai_entry_id: e.target.value })
                }
              >
                <option value="">Not configured</option>
                {apiKeyEntries.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {entry.name}
                  </option>
                ))}
              </select>
            </div>

            {apiKeyEntries.length === 0 && (
              <p className="text-xs text-slate-400">
                No vault entries in the api_key category yet. Add one in the
                vault, then pick it here.
              </p>
            )}

            <button
              type="submit"
              disabled={saveMutation.isPending}
              className={primaryButtonClass}
            >
              {saveMutation.isPending && (
                <Loader2 className="h-4 w-4 animate-spin" />
              )}
              Save provider keys
            </button>
          </form>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm text-slate-700">
              <span className="w-20">Anthropic</span>
              <StatusPill
                on={config.anthropic_configured}
                onLabel="Configured"
                offLabel="Not set"
              />
            </div>
            <div className="flex items-center gap-2 text-sm text-slate-700">
              <span className="w-20">OpenAI</span>
              <StatusPill
                on={config.openai_configured}
                onLabel="Configured"
                offLabel="Not set"
              />
            </div>
            <p className="text-xs text-slate-400">
              An admin configures the provider keys for the team.
            </p>
          </div>
        )}
      </div>

      <div className={cardClass}>
        <div className="mb-1 flex items-center gap-2">
          <h2 className="text-base font-semibold text-slate-900">
            Shield (PII protection)
          </h2>
          <StatusPill on={config.shield_enabled} onLabel="On" offLabel="Off" />
        </div>
        {config.shield_enabled ? (
          <p className="text-sm text-slate-500">
            PII in prompts and tool results is tokenized before it reaches the
            model, so names, emails, and secrets never leave your server in the
            clear. Hint level:{' '}
            <span className="font-medium text-slate-700">
              {config.shield_hint_level}
            </span>
            .
          </p>
        ) : (
          <p className="text-sm text-slate-500">
            Shield is off. An operator turns it on by setting the
            TRUSTISSUES_SHIELD_KEY environment variable. When on, PII in prompts
            and tool results is tokenized before it reaches the model.
          </p>
        )}
      </div>

      <div className={cardClass}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">
          Connect an AI assistant (MCP)
        </h2>
        <p className="mb-3 text-sm text-slate-500">
          Add this as a remote MCP or connector in Claude or ChatGPT and
          authenticate with an API key from the API keys tab (header X-API-Key).
        </p>
        <CodeBox value={config.mcp_url} />
        <p className="mt-3 text-sm text-slate-500">
          It exposes two tools: list_secrets returns the names of the vault
          entries you can reach, and use_secret injects a chosen secret into the
          request without ever revealing its value.
        </p>
      </div>

      <div className={cardClass}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">
          Use AI through the gateway
        </h2>
        <p className="mb-3 text-sm text-slate-500">
          Point your Anthropic or OpenAI SDK base URL at{' '}
          <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-700">
            {config.gateway_base_url}/anthropic
          </code>{' '}
          or{' '}
          <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs text-slate-700">
            {config.gateway_base_url}/openai
          </code>
          , and authenticate with an API key (header X-API-Key). The team key is
          injected server-side and PII is tokenized. Non-streaming only.
        </p>
        <CodeBox value={config.gateway_base_url} />
      </div>
    </div>
  );
}

// EncryptionTab is the operator surface for master-key rotation.
//
// The design constraint that drove this: an operator should not have to know the
// feature exists. A rotation is either policy work or an incident, and in the
// incident case the person at the keyboard may not be the person who deployed
// the instance. So the tab always answers three questions without being asked:
// which key this store is on, whether anything is unreadable, and what to do
// next. The status read needs no configuration, which means the naive-rotation
// case (someone changed TRUSTISSUES_VAULT_KEY in place) shows up here as a red
// banner rather than as blank fields in someone's vault entry a week later.
function EncryptionTab() {
  const queryClient = useQueryClient();
  const { data, isLoading, error } = useQuery<VaultKeyStatus>({
    queryKey: queryKeys.admin.vaultKey(),
    queryFn: api.admin.getVaultKeyStatus,
  });

  // A blocked sweep answers 409 with a full status body. That body is the most
  // useful thing on the screen (it names the rows nothing can open), so it is
  // held here rather than being reduced to a toast and thrown away.
  const [blocked, setBlocked] = useState<VaultKeyStatus | null>(null);

  const rekeyMutation = useMutation({
    mutationFn: api.admin.rekeyVault,
    onSuccess: (rep) => {
      setBlocked(null);
      queryClient.setQueryData(queryKeys.admin.vaultKey(), rep);
      if (rep.rows_converted === 0) {
        toast.success('Everything was already on the current key');
      } else {
        toast.success(`Re-encrypted ${rep.rows_converted} row(s)`);
      }
    },
    onError: (err) => {
      const body = err instanceof ApiError ? err.body : undefined;
      if (body && typeof body === 'object' && 'surfaces' in body) {
        setBlocked(body as VaultKeyStatus);
        toast.error('Sweep refused. Nothing was written.');
        return;
      }
      toast.error(errorMessage(err));
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
      </div>
    );
  }
  if (error || !data) {
    return (
      <div className={cardClass}>
        <p className="text-sm text-rose-600">{errorMessage(error)}</p>
      </div>
    );
  }

  const view = blocked ?? data;
  const state = view.status;

  return (
    <div className="space-y-4">
      <div className={cardClass}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">
          Encryption key
        </h2>
        <p className="mb-4 text-sm text-slate-500">
          Every secret, TOTP seed, invite code and channel config in this
          instance is encrypted with the master key. This is where you rotate it.
        </p>

        {state === 'blocked' && (
          <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
              <div className="text-sm text-rose-800">
                <p className="font-medium">
                  {view.values_unreadable} stored value(s) open under no key this
                  server holds.
                </p>
                <p className="mt-1">
                  Nothing has been written. The data is not lost, it is encrypted
                  with a key that is not loaded. Set{' '}
                  <code className="font-mono text-xs">
                    TRUSTISSUES_VAULT_KEY_PREVIOUS
                  </code>{' '}
                  to the key those values were sealed under, restart, and run the
                  sweep again.
                </p>
              </div>
            </div>
          </div>
        )}

        {state === 'needs_rekey' && (
          <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 p-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
              <div className="text-sm text-amber-800">
                <p className="font-medium">
                  {view.values_on_previous} value(s) are still encrypted with the
                  previous key.
                </p>
                <p className="mt-1">
                  Everything reads correctly right now, but only because the old
                  key is still loaded. Run the sweep, then remove{' '}
                  <code className="font-mono text-xs">
                    TRUSTISSUES_VAULT_KEY_PREVIOUS
                  </code>{' '}
                  from the environment and restart.
                </p>
              </div>
            </div>
          </div>
        )}

        {(state === 'already_current' || state === 'converted') && (
          <div className="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800">
            <p className="font-medium">
              Every stored value is encrypted with the current key.
            </p>
            {view.previous_key_configured && (
              <p className="mt-1">
                You can now remove{' '}
                <code className="font-mono text-xs">
                  TRUSTISSUES_VAULT_KEY_PREVIOUS
                </code>{' '}
                from the environment and restart. Until you do, the retired key
                is still loaded and still opens this data.
              </p>
            )}
          </div>
        )}

        <dl className="mb-4 grid gap-3 sm:grid-cols-2">
          <div>
            <dt className="text-xs font-medium text-slate-500">Current key</dt>
            <dd className="mt-0.5 font-mono text-sm text-slate-900">
              {view.current_key_fingerprint}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-slate-500">Previous key</dt>
            <dd className="mt-0.5 font-mono text-sm text-slate-900">
              {view.previous_key_configured ? (
                view.previous_key_fingerprint
              ) : (
                <span className="font-sans text-slate-400">not configured</span>
              )}
            </dd>
          </div>
        </dl>
        <p className="mb-4 text-xs text-slate-400">
          Those are short fingerprints, not keys. They exist so you can tell two
          keys apart without pasting one anywhere.
        </p>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => rekeyMutation.mutate()}
            disabled={rekeyMutation.isPending || !view.previous_key_configured}
            className={primaryButtonClass}
          >
            {rekeyMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ShieldCheck className="h-4 w-4" />
            )}
            Re-encrypt everything with the current key
          </button>
          <button
            onClick={() =>
              queryClient.invalidateQueries({
                queryKey: queryKeys.admin.vaultKey(),
              })
            }
            className="text-sm font-medium text-slate-500 hover:text-slate-900"
          >
            Refresh
          </button>
        </div>
        {!view.previous_key_configured && (
          <p className="mt-3 text-sm text-slate-500">
            To rotate: generate a new key, move the old value of{' '}
            <code className="font-mono text-xs">TRUSTISSUES_VAULT_KEY</code> to{' '}
            <code className="font-mono text-xs">
              TRUSTISSUES_VAULT_KEY_PREVIOUS
            </code>
            , put the new one in{' '}
            <code className="font-mono text-xs">TRUSTISSUES_VAULT_KEY</code>, and
            restart. Then come back here and press the button.
          </p>
        )}
      </div>

      {view.blockers.length > 0 && (
        <div className={cardClass}>
          <h2 className="mb-1 text-base font-semibold text-slate-900">
            Values nothing can open
          </h2>
          <p className="mb-4 text-sm text-slate-500">
            Showing {view.blockers.length} of {view.blockers_total}. Row ids
            only, never values.
          </p>
          <ul className="space-y-1 font-mono text-xs text-slate-700">
            {view.blockers.map((b, i) => (
              <li key={`${b.table}.${b.column}.${b.row_id}.${i}`}>
                {b.table}.{b.column}
                {b.setting_key ? `[${b.setting_key}]` : ''} @ {b.row_id}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className={cardClass}>
        <h2 className="mb-1 text-base font-semibold text-slate-900">Coverage</h2>
        <p className="mb-4 text-sm text-slate-500">
          Every column in this database that holds material derived from the
          master key. A rotation converts all of them or refuses.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-medium text-slate-500">
                <th className="py-2 pr-4">Column</th>
                <th className="py-2 pr-4">Holds</th>
                <th className="py-2 pr-4 text-right">Current</th>
                <th className="py-2 pr-4 text-right">Previous</th>
                <th className="py-2 text-right">Unreadable</th>
              </tr>
            </thead>
            <tbody>
              {view.surfaces.map((s) => (
                <tr
                  key={`${s.table}.${s.column}.${s.setting_key ?? ''}`}
                  className="border-b border-slate-100 last:border-0"
                >
                  <td className="py-2 pr-4 font-mono text-xs text-slate-800">
                    {s.table}.{s.column}
                    {s.setting_key ? `[${s.setting_key}]` : ''}
                  </td>
                  <td className="py-2 pr-4 text-slate-500">{s.why}</td>
                  <td className="py-2 pr-4 text-right tabular-nums text-slate-700">
                    {s.on_current}
                  </td>
                  <td
                    className={`py-2 pr-4 text-right tabular-nums ${
                      s.on_previous > 0
                        ? 'font-medium text-amber-700'
                        : 'text-slate-400'
                    }`}
                  >
                    {s.on_previous}
                  </td>
                  <td
                    className={`py-2 text-right tabular-nums ${
                      s.unreadable > 0
                        ? 'font-medium text-rose-700'
                        : 'text-slate-400'
                    }`}
                  >
                    {s.unreadable}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default function Settings() {
  const { isAdmin, isVaultOnly } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  // vault_only reaches this page solely to mint an extension API key, so it sees
  // Account and API keys and nothing else. This is presentation only: every
  // admin surface is enforced server-side with AdminOnly.
  const tabs: { id: SettingsTab; label: string; icon: typeof UserIcon }[] = [
    { id: 'account', label: 'Account', icon: UserIcon },
    { id: 'apikeys', label: 'API keys', icon: KeyRound },
    ...(isVaultOnly ? [] : ([{ id: 'ai', label: 'AI & MCP', icon: Bot }] as const)),
    ...(isAdmin
      ? ([
          { id: 'policy', label: 'Vault policy', icon: ShieldCheck },
          { id: 'session', label: 'Sessions', icon: Clock },
          { id: 'email', label: 'Email', icon: Mail },
          { id: 'channels', label: 'Alerts', icon: Bell },
          { id: 'encryption', label: 'Encryption', icon: Lock },
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
      {activeTab === 'apikeys' && <ApiKeysTab />}
      {activeTab === 'ai' && <AITab />}
      {activeTab === 'policy' && isAdmin && <PolicyTab />}
      {activeTab === 'session' && isAdmin && <SessionTab />}
      {activeTab === 'email' && isAdmin && <EmailTab />}
      {activeTab === 'channels' && isAdmin && <ChannelsTab />}
      {activeTab === 'encryption' && isAdmin && <EncryptionTab />}
    </Layout>
  );
}
