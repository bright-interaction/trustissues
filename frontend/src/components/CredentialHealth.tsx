import { useMemo, useState } from 'react';
import { ChevronDown, ChevronUp, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { VaultEntry } from '@/lib/vault-types';
import { analyzeCredentialHealth } from '@/lib/credential-health';

export default function CredentialHealth({ entries }: { entries: VaultEntry[] }) {
  const [expanded, setExpanded] = useState(false);
  const report = useMemo(() => analyzeCredentialHealth(entries), [entries]);

  if (report.checked === 0) return null;
  const clean = report.issues.length === 0;

  return (
    <section className={`rounded-xl border p-4 ${clean ? 'border-emerald-200 bg-emerald-50' : 'border-amber-200 bg-amber-50'}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex gap-3">
          {clean ? <ShieldCheck className="mt-0.5 h-5 w-5 text-emerald-600" /> : <ShieldAlert className="mt-0.5 h-5 w-5 text-amber-600" />}
          <div>
            <h3 className={`text-sm font-semibold ${clean ? 'text-emerald-900' : 'text-amber-900'}`}>Credential health</h3>
            <p className={`mt-0.5 text-xs ${clean ? 'text-emerald-700' : 'text-amber-800'}`}>
              {clean ? `${report.checked} credentials passed local checks.` : `${report.issues.length} of ${report.checked} credentials need attention.`}
            </p>
          </div>
        </div>
        {!clean && (
          <button type="button" onClick={() => setExpanded((value) => !value)} className="inline-flex items-center gap-1 rounded-lg border border-amber-300 bg-white px-2.5 py-1.5 text-xs font-medium text-amber-800 hover:bg-amber-100">
            {expanded ? 'Hide' : 'Review'}
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        )}
      </div>

      {!clean && (
        <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
          <div className="rounded-lg bg-white px-2 py-2"><strong className="block text-base text-amber-900">{report.weak}</strong><span className="text-amber-700">Weak</span></div>
          <div className="rounded-lg bg-white px-2 py-2"><strong className="block text-base text-amber-900">{report.reused}</strong><span className="text-amber-700">Reused</span></div>
          <div className="rounded-lg bg-white px-2 py-2"><strong className="block text-base text-amber-900">{report.old}</strong><span className="text-amber-700">Older than 1 year</span></div>
        </div>
      )}

      {expanded && (
        <ul className="mt-3 space-y-2">
          {report.issues.map((issue) => (
            <li key={issue.entryId} className="rounded-lg border border-amber-200 bg-white px-3 py-2">
              <p className="text-sm font-medium text-slate-900">{issue.entryName}</p>
              <p className="mt-0.5 text-xs text-slate-600">{issue.reasons.join('; ')}.</p>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-[11px] text-slate-500">Checked locally in this unlocked tab. Password values are not uploaded for analysis.</p>
    </section>
  );
}
