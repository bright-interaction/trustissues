import { Fragment, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity as ActivityIcon,
  Loader2,
  Filter,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  Download,
} from 'lucide-react';
import { api } from '@/lib/api';
import { queryKeys } from '@/lib/query-keys';
import Layout from '@/components/Layout';
import { useAuth } from '@/hooks/useAuth';
import type { ActivityEntry, ManagedUser } from '@/lib/types';

const PAGE_SIZE = 50;

function formatTime(dateStr: string): string {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();

  const time = d.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  if (isToday) return time;

  return `${d.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
  })} ${time}`;
}

/** Abbreviate an IP address for display: show first 3 octets + "xxx" */
function abbreviateIP(ip: string | null): string {
  if (!ip) return '-';
  // Strip port if present (e.g. 192.168.1.5:43210 -> 192.168.1.5)
  const clean =
    ip.includes(':') && !ip.includes('[')
      ? ip.split(':').length === 2
        ? ip.split(':')[0]
        : ip
      : ip;
  const parts = clean.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
  }
  return clean;
}

/** Return Tailwind color classes for action badge based on category. */
function actionBadgeClasses(action: string): string {
  if (action.startsWith('vault.')) {
    return 'bg-blue-50 text-blue-700 ring-1 ring-blue-200';
  }
  if (action.startsWith('rotation.')) {
    return 'bg-purple-50 text-purple-700 ring-1 ring-purple-200';
  }
  if (action.startsWith('settings.')) {
    return 'bg-amber-50 text-amber-700 ring-1 ring-amber-200';
  }
  if (action.startsWith('user.') || action.startsWith('invitation.')) {
    return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
  }
  if (action.startsWith('auth.')) {
    return 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200';
  }
  return 'bg-slate-100 text-slate-700 ring-1 ring-slate-200';
}

// Known action categories for the filter dropdown (static list so it does not
// depend on current page data).
const ACTION_CATEGORIES = [
  { prefix: 'auth.', label: 'auth.*' },
  { prefix: 'invitation.', label: 'invitation.*' },
  { prefix: 'rotation.', label: 'rotation.*' },
  { prefix: 'settings.', label: 'settings.*' },
  { prefix: 'user.', label: 'user.*' },
  { prefix: 'vault.', label: 'vault.*' },
];

export default function ActivityPage() {
  const { isAdmin } = useAuth();
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [page, setPage] = useState(0);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [exporting, setExporting] = useState<'csv' | 'json' | null>(null);

  const offset = page * PAGE_SIZE;

  const { data: users = [] } = useQuery<ManagedUser[]>({
    queryKey: queryKeys.admin.users(),
    queryFn: api.admin.listUsers,
    enabled: isAdmin,
  });

  const { data: activityData, isLoading } = useQuery({
    queryKey: queryKeys.activity.list({
      user_id: userFilter || undefined,
      action: actionFilter || undefined,
      offset,
    }),
    queryFn: async (): Promise<{ entries: ActivityEntry[]; total: number }> => {
      const res = await api.activity.list({
        user_id: userFilter || undefined,
        action: actionFilter || undefined,
        limit: PAGE_SIZE,
        offset,
      });
      return { entries: res.entries, total: res.total };
    },
    refetchInterval: 30_000,
  });

  const activity = activityData?.entries ?? [];
  const total = activityData?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // Combine static categories with any additional actions seen in data.
  const seenActions = Array.from(new Set(activity.map((a) => a.action))).sort();
  const allFilterOptions = Array.from(
    new Set([...ACTION_CATEGORIES.map((c) => c.label), ...seenActions])
  ).sort();

  const handleUserFilterChange = (value: string) => {
    setUserFilter(value);
    setPage(0);
    setExpandedRow(null);
  };

  const handleActionFilterChange = (value: string) => {
    setActionFilter(value);
    setPage(0);
    setExpandedRow(null);
  };

  const toggleRow = (id: number) => {
    setExpandedRow(expandedRow === id ? null : id);
  };

  async function handleExport(format: 'csv' | 'json') {
    setExporting(format);
    try {
      const params = new URLSearchParams();
      if (userFilter) params.set('user_id', userFilter);
      if (actionFilter) params.set('action', actionFilter);
      const res = await fetch(`/api/activity/export/${format}?${params}`, {
        credentials: 'same-origin',
      });
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `activity-export.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // silently fail
    } finally {
      setExporting(null);
    }
  }

  return (
    <Layout>
      <div className="mb-6">
        <h1
          data-testid="page-activity"
          className="text-xl font-semibold text-slate-900"
        >
          Activity Log
        </h1>
        <p className="text-sm text-slate-500">
          Every touch of the vault, on the record
        </p>
      </div>

      <div className="mb-4 flex items-center gap-3">
        <Filter className="h-4 w-4 text-slate-400" />
        {isAdmin && (
          <select
            value={userFilter}
            onChange={(e) => handleUserFilterChange(e.target.value)}
            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 outline-none focus:border-slate-400"
          >
            <option value="">All users</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.email}
              </option>
            ))}
          </select>
        )}
        <select
          value={actionFilter}
          onChange={(e) => handleActionFilterChange(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 outline-none focus:border-slate-400"
        >
          <option value="">All actions</option>
          {allFilterOptions.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <div className="ml-auto flex items-center gap-2">
          <button
            onClick={() => handleExport('csv')}
            disabled={exporting !== null || total === 0}
            className="flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-600 transition-colors hover:bg-slate-50 disabled:opacity-40"
            title="Export as CSV"
          >
            {exporting === 'csv' ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            CSV
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={exporting !== null || total === 0}
            className="flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs text-slate-600 transition-colors hover:bg-slate-50 disabled:opacity-40"
            title="Export as JSON"
          >
            {exporting === 'json' ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            JSON
          </button>
          {total > 0 && (
            <span className="text-xs text-slate-400">
              {total.toLocaleString()} entries
            </span>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
        </div>
      ) : activity.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white px-4 py-12 text-center">
          <ActivityIcon className="mx-auto mb-2 h-8 w-8 text-slate-300" />
          <p className="text-sm text-slate-500">No activity recorded</p>
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  <th className="w-8 px-2 py-2.5" />
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Time
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    User
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Action
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    IP Address
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody>
                {activity.map((entry, i) => {
                  const isExpanded = expandedRow === entry.id;
                  return (
                    <Fragment key={entry.id}>
                      <tr
                        onClick={() => toggleRow(entry.id)}
                        className={`cursor-pointer transition-colors hover:bg-slate-50 ${
                          i < activity.length - 1 && !isExpanded
                            ? 'border-b border-slate-50'
                            : ''
                        }`}
                      >
                        <td className="px-2 py-2.5 text-slate-400">
                          {isExpanded ? (
                            <ChevronDown className="h-3.5 w-3.5" />
                          ) : (
                            <ChevronRight className="h-3.5 w-3.5" />
                          )}
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-500">
                          {formatTime(entry.created_at)}
                        </td>
                        <td className="px-4 py-2.5 text-sm text-slate-700">
                          {entry.user_email || '-'}
                        </td>
                        <td className="px-4 py-2.5">
                          <span
                            className={`inline-block rounded-md px-2 py-0.5 text-xs font-medium ${actionBadgeClasses(entry.action)}`}
                          >
                            {entry.action}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-slate-500">
                          {abbreviateIP(entry.ip_address)}
                        </td>
                        <td className="max-w-md truncate px-4 py-2.5 text-sm text-slate-500">
                          {entry.detail || '-'}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr
                          className={
                            i < activity.length - 1
                              ? 'border-b border-slate-100'
                              : ''
                          }
                        >
                          <td colSpan={6} className="bg-slate-50/50 px-4 py-3">
                            <div className="grid grid-cols-1 gap-2 pl-6 text-xs sm:grid-cols-2">
                              <div>
                                <span className="font-semibold text-slate-600">
                                  Full Detail:
                                </span>{' '}
                                <span className="text-slate-500">
                                  {entry.detail || 'None'}
                                </span>
                              </div>
                              <div>
                                <span className="font-semibold text-slate-600">
                                  IP Address:
                                </span>{' '}
                                <span className="font-mono text-slate-500">
                                  {entry.ip_address || 'Unknown'}
                                </span>
                              </div>
                              <div className="sm:col-span-2">
                                <span className="font-semibold text-slate-600">
                                  User Agent:
                                </span>{' '}
                                <span className="break-all text-slate-500">
                                  {entry.user_agent || 'Unknown'}
                                </span>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between">
              <div className="text-xs text-slate-500">
                Showing {offset + 1} to {Math.min(offset + PAGE_SIZE, total)} of{' '}
                {total.toLocaleString()}
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage(0)}
                  disabled={page === 0}
                  className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                  title="First page"
                >
                  <ChevronsLeft className="h-4 w-4" />
                </button>
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                  title="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <span className="px-3 text-sm text-slate-700">
                  Page {page + 1} of {totalPages}
                </span>
                <button
                  onClick={() =>
                    setPage((p) => Math.min(totalPages - 1, p + 1))
                  }
                  disabled={page >= totalPages - 1}
                  className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                  title="Next page"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
                <button
                  onClick={() => setPage(totalPages - 1)}
                  disabled={page >= totalPages - 1}
                  className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
                  title="Last page"
                >
                  <ChevronsRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </Layout>
  );
}
