import { useState, type FormEvent } from 'react';
import { Navigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import {
  Copy,
  Loader2,
  Mail,
  Plus,
  RefreshCw,
  Trash2,
  Users as UsersIcon,
  X,
} from 'lucide-react';
import Layout from '@/components/Layout';
import { api, ApiError } from '@/lib/api';
import { queryKeys } from '@/lib/query-keys';
import { useAuth } from '@/hooks/useAuth';
import type { Invitation, ManagedUser, Role } from '@/lib/types';

const ROLE_OPTIONS: { value: Role; label: string; hint: string }[] = [
  { value: 'admin', label: 'Admin', hint: 'Sees everything, manages everyone' },
  { value: 'user', label: 'User', hint: 'Owns their own vault entries' },
  {
    value: 'vault_only',
    label: 'Vault only',
    hint: 'Locked to the vault UI, nothing else',
  },
];

function roleBadgeClasses(role: Role): string {
  switch (role) {
    case 'admin':
      return 'bg-amber-50 text-amber-700 ring-1 ring-amber-200';
    case 'vault_only':
      return 'bg-purple-50 text-purple-700 ring-1 ring-purple-200';
    default:
      return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return 'Something went wrong';
}

interface CreateUserForm {
  name: string;
  email: string;
  password: string;
  role: Role;
}

const emptyCreateForm: CreateUserForm = {
  name: '',
  email: '',
  password: '',
  role: 'user',
};

interface InviteForm {
  name: string;
  email: string;
  role: Role;
  send_email: boolean;
}

const emptyInviteForm: InviteForm = {
  name: '',
  email: '',
  role: 'user',
  send_email: true,
};

export default function UsersPage() {
  const { user: currentUser, isAdmin, isLoading } = useAuth();
  const queryClient = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState<CreateUserForm>(emptyCreateForm);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteForm, setInviteForm] = useState<InviteForm>(emptyInviteForm);
  const [resetTarget, setResetTarget] = useState<ManagedUser | null>(null);
  const [resetPassword, setResetPassword] = useState('');

  const { data: users = [], isLoading: usersLoading } = useQuery<ManagedUser[]>(
    {
      queryKey: queryKeys.admin.users(),
      queryFn: api.admin.listUsers,
      enabled: isAdmin,
    }
  );

  const { data: invitations = [] } = useQuery<Invitation[]>({
    queryKey: queryKeys.admin.invitations(),
    queryFn: api.admin.listInvitations,
    enabled: isAdmin,
  });

  const invalidateUsers = () =>
    queryClient.invalidateQueries({ queryKey: queryKeys.admin.users() });
  const invalidateInvitations = () =>
    queryClient.invalidateQueries({ queryKey: queryKeys.admin.invitations() });

  const createUserMutation = useMutation({
    mutationFn: (data: CreateUserForm) => api.admin.createUser(data),
    onSuccess: () => {
      toast.success('User created');
      setShowCreate(false);
      setCreateForm(emptyCreateForm);
      invalidateUsers();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const updateUserMutation = useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: string;
      data: { role?: Role; disabled?: boolean };
    }) => api.admin.updateUser(id, data),
    onSuccess: () => {
      toast.success('User updated');
      invalidateUsers();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const deleteUserMutation = useMutation({
    mutationFn: (id: string) => api.admin.deleteUser(id),
    onSuccess: () => {
      toast.success('User deleted');
      invalidateUsers();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const resetPasswordMutation = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      api.admin.resetPassword(id, password),
    onSuccess: () => {
      toast.success('Password reset');
      setResetTarget(null);
      setResetPassword('');
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const createInviteMutation = useMutation({
    mutationFn: (data: InviteForm) => api.admin.createInvitation(data),
    onSuccess: (inv) => {
      toast.success(`Invitation created for ${inv.email}`);
      setShowInvite(false);
      setInviteForm(emptyInviteForm);
      invalidateInvitations();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const deleteInviteMutation = useMutation({
    mutationFn: (id: string) => api.admin.deleteInvitation(id),
    onSuccess: () => {
      toast.success('Invitation deleted');
      invalidateInvitations();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const resendInviteMutation = useMutation({
    mutationFn: (id: string) => api.admin.resendInvitation(id),
    onSuccess: () => toast.success('Invitation resent'),
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (!isLoading && !isAdmin) {
    return <Navigate to="/vault" replace />;
  }

  function handleCreateUser(e: FormEvent) {
    e.preventDefault();
    if (createForm.password.length < 12) {
      toast.error('Password must be at least 12 characters');
      return;
    }
    createUserMutation.mutate(createForm);
  }

  function handleCreateInvite(e: FormEvent) {
    e.preventDefault();
    createInviteMutation.mutate(inviteForm);
  }

  function copyInviteLink(inv: Invitation) {
    const link = `${window.location.origin}/invite?code=${encodeURIComponent(inv.code)}`;
    navigator.clipboard
      .writeText(link)
      .then(() => toast.success('Invite link copied'))
      .catch(() => toast.error('Could not copy link'));
  }

  const inputClass =
    'w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition-colors focus:border-slate-400 focus:ring-0';

  return (
    <Layout>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1
            data-testid="page-users"
            className="text-xl font-semibold text-slate-900"
          >
            Users
          </h1>
          <p className="text-sm text-slate-500">
            The short list of people you trust
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowInvite(true)}
            className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50"
          >
            <Mail className="h-4 w-4" />
            Invite
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800"
          >
            <Plus className="h-4 w-4" />
            New user
          </button>
        </div>
      </div>

      {usersLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
        </div>
      ) : users.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white px-4 py-12 text-center">
          <UsersIcon className="mx-auto mb-2 h-8 w-8 text-slate-300" />
          <p className="text-sm text-slate-500">No users yet</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Name
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Email
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Role
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Entries
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Status
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((u, i) => {
                const isSelf = u.id === currentUser?.id;
                return (
                  <tr
                    key={u.id}
                    className={
                      i < users.length - 1 ? 'border-b border-slate-50' : ''
                    }
                  >
                    <td className="px-4 py-2.5 text-slate-900">{u.name}</td>
                    <td className="px-4 py-2.5 text-slate-600">{u.email}</td>
                    <td className="px-4 py-2.5">
                      {isSelf ? (
                        <span
                          className={`inline-block rounded-md px-2 py-0.5 text-xs font-medium ${roleBadgeClasses(u.role)}`}
                        >
                          {u.role}
                        </span>
                      ) : (
                        <select
                          value={u.role}
                          onChange={(e) =>
                            updateUserMutation.mutate({
                              id: u.id,
                              data: { role: e.target.value as Role },
                            })
                          }
                          className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-slate-700 outline-none focus:border-slate-400"
                        >
                          {ROLE_OPTIONS.map((r) => (
                            <option key={r.value} value={r.value}>
                              {r.label}
                            </option>
                          ))}
                        </select>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-slate-600">
                      {u.entry_count}
                    </td>
                    <td className="px-4 py-2.5">
                      {u.disabled ? (
                        <span className="inline-block rounded-md bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-200">
                          disabled
                        </span>
                      ) : (
                        <span className="inline-block rounded-md bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200">
                          active
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => {
                            setResetTarget(u);
                            setResetPassword('');
                          }}
                          className="text-xs text-slate-500 hover:text-slate-900"
                        >
                          Reset password
                        </button>
                        {!isSelf && (
                          <>
                            <button
                              onClick={() =>
                                updateUserMutation.mutate({
                                  id: u.id,
                                  data: { disabled: !u.disabled },
                                })
                              }
                              className="text-xs text-slate-500 hover:text-slate-900"
                            >
                              {u.disabled ? 'Enable' : 'Disable'}
                            </button>
                            <button
                              onClick={() => {
                                if (
                                  window.confirm(
                                    `Delete ${u.email}?\n\n` +
                                      `Their ${u.entry_count} personal secret${u.entry_count === 1 ? '' : 's'} will be deleted permanently. ` +
                                      `Secrets they created inside shared collections stay with the team and transfer to you. ` +
                                      `Any service keys they issued are revoked, so services using them must be re-provisioned.`
                                  )
                                ) {
                                  deleteUserMutation.mutate(u.id);
                                }
                              }}
                              className="text-slate-400 hover:text-red-600"
                              title="Delete user"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Invitations */}
      <div className="mb-3 mt-8">
        <h2 className="text-base font-semibold text-slate-900">Invitations</h2>
        <p className="text-sm text-slate-500">
          Pending invites and their fates
        </p>
      </div>
      {invitations.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white px-4 py-8 text-center">
          <p className="text-sm text-slate-500">No invitations</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Email
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Role
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Status
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Expires
                </th>
                <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {invitations.map((inv, i) => (
                <tr
                  key={inv.id}
                  className={
                    i < invitations.length - 1 ? 'border-b border-slate-50' : ''
                  }
                >
                  <td className="px-4 py-2.5 text-slate-700">{inv.email}</td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block rounded-md px-2 py-0.5 text-xs font-medium ${roleBadgeClasses(inv.role)}`}
                    >
                      {inv.role}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">
                    {inv.status}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">
                    {inv.expires_at
                      ? new Date(inv.expires_at).toLocaleDateString()
                      : '-'}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      {inv.status === 'pending' && (
                        <>
                          <button
                            onClick={() => copyInviteLink(inv)}
                            className="text-slate-400 hover:text-slate-900"
                            title="Copy invite link"
                          >
                            <Copy className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => resendInviteMutation.mutate(inv.id)}
                            className="text-slate-400 hover:text-slate-900"
                            title="Resend invitation email"
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                          </button>
                        </>
                      )}
                      <button
                        onClick={() => deleteInviteMutation.mutate(inv.id)}
                        className="text-slate-400 hover:text-red-600"
                        title="Delete invitation"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create user modal */}
      {showCreate && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40 px-4">
          <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-semibold text-slate-900">
                New user
              </h2>
              <button
                onClick={() => setShowCreate(false)}
                className="text-slate-400 hover:text-slate-900"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Name
                </label>
                <input
                  type="text"
                  value={createForm.name}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, name: e.target.value })
                  }
                  required
                  className={inputClass}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Email
                </label>
                <input
                  type="email"
                  value={createForm.email}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, email: e.target.value })
                  }
                  required
                  className={inputClass}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Password
                </label>
                <input
                  type="password"
                  value={createForm.password}
                  onChange={(e) =>
                    setCreateForm({ ...createForm, password: e.target.value })
                  }
                  required
                  minLength={12}
                  autoComplete="new-password"
                  className={inputClass}
                  placeholder="Minimum 12 characters"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Role
                </label>
                <select
                  value={createForm.role}
                  onChange={(e) =>
                    setCreateForm({
                      ...createForm,
                      role: e.target.value as Role,
                    })
                  }
                  className={inputClass}
                >
                  {ROLE_OPTIONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-xs text-slate-400">
                  {
                    ROLE_OPTIONS.find((r) => r.value === createForm.role)?.hint
                  }
                </p>
              </div>
              <button
                type="submit"
                disabled={createUserMutation.isPending}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-50"
              >
                {createUserMutation.isPending && (
                  <Loader2 className="h-4 w-4 animate-spin" />
                )}
                Create user
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Invite modal */}
      {showInvite && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40 px-4">
          <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-semibold text-slate-900">
                Invite a colleague
              </h2>
              <button
                onClick={() => setShowInvite(false)}
                className="text-slate-400 hover:text-slate-900"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={handleCreateInvite} className="space-y-4">
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Name
                </label>
                <input
                  type="text"
                  value={inviteForm.name}
                  onChange={(e) =>
                    setInviteForm({ ...inviteForm, name: e.target.value })
                  }
                  required
                  className={inputClass}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Email
                </label>
                <input
                  type="email"
                  value={inviteForm.email}
                  onChange={(e) =>
                    setInviteForm({ ...inviteForm, email: e.target.value })
                  }
                  required
                  className={inputClass}
                />
              </div>
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  Role
                </label>
                <select
                  value={inviteForm.role}
                  onChange={(e) =>
                    setInviteForm({
                      ...inviteForm,
                      role: e.target.value as Role,
                    })
                  }
                  className={inputClass}
                >
                  {ROLE_OPTIONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-xs text-slate-400">
                  {ROLE_OPTIONS.find((r) => r.value === inviteForm.role)?.hint}
                </p>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={inviteForm.send_email}
                  onChange={(e) =>
                    setInviteForm({
                      ...inviteForm,
                      send_email: e.target.checked,
                    })
                  }
                  className="h-4 w-4 rounded border-slate-300"
                />
                Send the invitation by email (needs SMTP configured)
              </label>
              <button
                type="submit"
                disabled={createInviteMutation.isPending}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-50"
              >
                {createInviteMutation.isPending && (
                  <Loader2 className="h-4 w-4 animate-spin" />
                )}
                Create invitation
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Reset password modal */}
      {resetTarget && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/40 px-4">
          <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-lg">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-base font-semibold text-slate-900">
                Reset password for {resetTarget.email}
              </h2>
              <button
                onClick={() => setResetTarget(null)}
                className="text-slate-400 hover:text-slate-900"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (resetPassword.length < 12) {
                  toast.error('Password must be at least 12 characters');
                  return;
                }
                resetPasswordMutation.mutate({
                  id: resetTarget.id,
                  password: resetPassword,
                });
              }}
              className="space-y-4"
            >
              <div>
                <label className="mb-1.5 block text-sm font-medium text-slate-700">
                  New password
                </label>
                <input
                  type="password"
                  value={resetPassword}
                  onChange={(e) => setResetPassword(e.target.value)}
                  required
                  minLength={12}
                  autoComplete="new-password"
                  className={inputClass}
                  placeholder="Minimum 12 characters"
                  autoFocus
                />
              </div>
              <button
                type="submit"
                disabled={resetPasswordMutation.isPending}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-slate-800 disabled:opacity-50"
              >
                {resetPasswordMutation.isPending && (
                  <Loader2 className="h-4 w-4 animate-spin" />
                )}
                Reset password
              </button>
            </form>
          </div>
        </div>
      )}
    </Layout>
  );
}
