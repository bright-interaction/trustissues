import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Filter,
  Loader2,
  ShieldCheck,
} from 'lucide-react';
import { api } from '@/lib/api';
import { queryKeys } from '@/lib/query-keys';
import Layout from '@/components/Layout';
import type { CapabilityLogEntry } from '@/lib/types';

const PAGE_SIZE = 50;

/**
 * The events capability_log records, in the order they matter to somebody
 * reading this page during an incident: what was refused, then what was spent.
 */
const EVENT_OPTIONS = ['issued', 'used', 'denied'] as const;

function formatTime(dateStr: string): string {
  if (!dateStr) return '';
  // SQLite datetime('now') has no zone marker; it is UTC, and without the Z the
  // browser reads it as local and shows an access that happened at 09:00 UTC as
  // 09:00 local. On a trail whose whole job is "when did this happen", an hour
  // of silent drift is not cosmetic.
  const normalised = /(Z|[+-]\d{2}:?\d{2})$/.test(dateStr)
    ? dateStr
    : `${dateStr.replace(' ', 'T')}Z`;
  const d = new Date(normalised);
  if (Number.isNaN(d.getTime())) return dateStr;
  const now = new Date();
  const time = d.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  if (d.toDateString() === now.toDateString()) return time;
  return `${d.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
  })} ${time}`;
}

function eventBadgeClasses(event: string): string {
  switch (event) {
    case 'denied':
      return 'bg-red-50 text-red-700 ring-1 ring-red-200';
    case 'used':
      return 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200';
    case 'issued':
      return 'bg-blue-50 text-blue-700 ring-1 ring-blue-200';
    default:
      return 'bg-slate-50 text-slate-600 ring-1 ring-slate-200';
  }
}

/**
 * A secret name that could not be opened.
 *
 * The column is sealed under the audit DEK. If that key is unavailable the API
 * returns this marker rather than cleartext, and the row still says who did what
 * and when. Rendering it as ordinary text would read as a secret actually called
 * "[unavailable]".
 */
const UNAVAILABLE = '[unavailable]';

function SecretName({ entry }: { entry: CapabilityLogEntry }) {
  if (!entry.secret_name) {
    return <span className="text-slate-400">-</span>;
  }
  if (entry.secret_name === UNAVAILABLE) {
    return (
      <span
        className="text-amber-600"
        title="This name is sealed under the audit key and could not be opened. The access itself is still recorded."
      >
        unavailable
      </span>
    );
  }
  return (
    <span className="font-medium text-slate-900">{entry.secret_name}</span>
  );
}

/**
 * CREDENTIAL ACCESS: who spent which secret, when, and to where.
 *
 * capability_log has recorded this since 00020 and nothing read it, so the
 * receipt the whole bridge design exists to produce was invisible in the
 * product. This page is that receipt.
 *
 * It is deliberately its own page rather than a tab on Activity. The activity
 * log records what PEOPLE did to the vault; this records what AGENTS did with
 * its contents, which is a different question asked by a different person at a
 * different time (during an incident, about a credential, not about a user).
 * Folding them together would have meant one filter set that answers neither
 * well.
 */
export default function CredentialAccess() {
  const [page, setPage] = useState(0);
  const [agentFilter, setAgentFilter] = useState('');
  const [eventFilter, setEventFilter] = useState('');

  const offset = page * PAGE_SIZE;

  const { data, isLoading } = useQuery({
    queryKey: queryKeys.capabilityLog.list({
      agent: agentFilter,
      event: eventFilter,
      offset,
    }),
    queryFn: () =>
      api.capabilityLog.list({
        agent_id: agentFilter || undefined,
        event: eventFilter || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
  });

  const entries = data?.entries ?? [];
  const total = data?.total ?? 0;
  const agents = data?.agents ?? [];
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const resetTo = (fn: () => void) => {
    fn();
    setPage(0);
  };

  return (
    <Layout>
      <div className="mb-6">
        <h1
          data-testid="page-credential-access"
          className="text-xl font-semibold text-slate-900"
        >
          Credential Access
        </h1>
        <p className="text-sm text-slate-500">
          Which agent spent which secret, when, and to where
        </p>
      </div>

      <div className="mb-4 flex items-center gap-3">
        <Filter className="h-4 w-4 text-slate-400" />
        <select
          value={agentFilter}
          onChange={(e) => resetTo(() => setAgentFilter(e.target.value))}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 outline-none focus:border-slate-400"
        >
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <select
          value={eventFilter}
          onChange={(e) => resetTo(() => setEventFilter(e.target.value))}
          className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 outline-none focus:border-slate-400"
        >
          <option value="">All events</option>
          {EVENT_OPTIONS.map((ev) => (
            <option key={ev} value={ev}>
              {ev}
            </option>
          ))}
        </select>
        {total > 0 && (
          <span className="ml-auto text-xs text-slate-400">
            {total.toLocaleString()} {total === 1 ? 'access' : 'accesses'}
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-5 w-5 animate-spin text-slate-400" />
        </div>
      ) : entries.length === 0 ? (
        // An empty audit surface reads as a broken one unless it says what it
        // WOULD show. On a new instance this page is empty until the first agent
        // spends a credential, and an operator who lands here needs to know that
        // is the expected state rather than a missing feature.
        <div className="rounded-xl border border-slate-200 bg-white px-6 py-12 text-center">
          <ShieldCheck className="mx-auto mb-3 h-8 w-8 text-slate-300" />
          <p className="text-sm font-medium text-slate-700">
            {agentFilter || eventFilter
              ? 'No credential access matches this filter'
              : 'No credential access recorded yet'}
          </p>
          <p className="mx-auto mt-1 max-w-md text-sm text-slate-500">
            {agentFilter || eventFilter
              ? 'Clear the filters to see the whole trail.'
              : 'Every capability token this vault issues, spends or refuses is recorded here, including the secret it was for. Rows appear once an agent requests a credential.'}
          </p>
        </div>
      ) : (
        <>
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Time
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Agent
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Secret
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Event
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Destination
                  </th>
                  <th className="px-4 py-2.5 text-xs font-semibold text-slate-600">
                    Outcome
                  </th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => (
                  <tr
                    key={entry.id}
                    className={i > 0 ? 'border-t border-slate-100' : undefined}
                  >
                    <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-500">
                      {formatTime(entry.issued_at)}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-700">
                      {entry.agent_id}
                    </td>
                    <td className="px-4 py-2.5">
                      <SecretName entry={entry} />
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium ${eventBadgeClasses(
                          entry.event,
                        )}`}
                      >
                        {entry.event}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-600">
                      {entry.destination ? (
                        <span className="break-all">
                          {entry.method ? (
                            <span className="mr-1 font-mono text-slate-400">
                              {entry.method}
                            </span>
                          ) : null}
                          {entry.destination}
                        </span>
                      ) : (
                        <span className="text-slate-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs">
                      {entry.error ? (
                        <span className="text-red-600">{entry.error}</span>
                      ) : entry.status_code != null ? (
                        <span
                          className={
                            entry.status_code >= 400
                              ? 'text-red-600'
                              : 'text-slate-600'
                          }
                        >
                          {entry.status_code}
                        </span>
                      ) : (
                        <span className="text-slate-400">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

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
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
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
