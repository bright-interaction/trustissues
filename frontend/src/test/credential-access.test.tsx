import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { CapabilityLogEntry } from '@/lib/types';

// The Credential Access page shipped 2026-08-10 as the reader for capability_log,
// closing the "nothing reads the capability trail" risk that stood since 00020.
// It shipped with no test. This page is an AUDIT surface, and the failure modes
// of an audit surface are quieter than the ones of a normal page: it does not
// crash, it shows you fewer rows than exist, or it shows a marker as if it were
// data, and either way you conclude something about an incident that is not true.
//
// So these pin the four places where being subtly wrong is worse than being
// broken, not the layout.

vi.mock('@/components/Layout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

const listMock = vi.fn();
vi.mock('@/lib/api', () => ({
  api: { capabilityLog: { list: (...a: unknown[]) => listMock(...a) } },
}));

import CredentialAccess from '@/pages/CredentialAccess';

function entry(over: Partial<CapabilityLogEntry> = {}): CapabilityLogEntry {
  return {
    id: 'c1',
    agent_id: 'agent-alpha',
    secret_id: 's1',
    secret_name: 'Stripe prod',
    destination: 'api.stripe.com',
    method: 'POST',
    event: 'used',
    status_code: 200,
    error: '',
    issued_at: '2026-08-10 09:00:00',
    ...over,
  };
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <CredentialAccess />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

beforeEach(() => listMock.mockReset());
afterEach(() => vi.clearAllMocks());

describe('a sealed secret name is not rendered as a secret called "[unavailable]"', () => {
  // The API returns the literal string "[unavailable]" when the audit DEK cannot
  // open the name, so the row still says who did what and when. Printing it as
  // ordinary text would read as an entry actually NAMED "[unavailable]", which
  // during an incident is a fact about the vault that is simply false.
  it('shows the marker as an annotated state, not as the name', async () => {
    listMock.mockResolvedValue({
      entries: [entry({ secret_name: '[unavailable]' })],
      total: 1,
      agents: ['agent-alpha'],
    });
    renderPage();

    const cell = await screen.findByText('unavailable');
    expect(cell).toBeInTheDocument();
    // The brackets are the tell: if they survive to the DOM, it is being printed
    // verbatim rather than recognised.
    expect(screen.queryByText('[unavailable]')).not.toBeInTheDocument();
    expect(cell).toHaveAttribute('title', expect.stringContaining('sealed'));
  });

  it('still renders a real name normally', async () => {
    listMock.mockResolvedValue({
      entries: [entry({ secret_name: 'Stripe prod' })],
      total: 1,
      agents: ['agent-alpha'],
    });
    renderPage();
    expect(await screen.findByText('Stripe prod')).toBeInTheDocument();
  });
});

describe('a naive SQLite timestamp is read as UTC, not as local time', () => {
  // SQLite's datetime('now') carries no zone marker. Handing "2026-08-10 09:00:00"
  // straight to new Date() makes the browser read it as LOCAL, so an access that
  // happened at 09:00 UTC displays as 09:00 in Stockholm: a silent two-hour lie
  // on the one column whose entire job is "when did this happen".
  it('renders the instant that the UTC string denotes', async () => {
    listMock.mockResolvedValue({
      entries: [entry({ issued_at: '2026-08-10 09:00:00' })],
      total: 1,
      agents: ['agent-alpha'],
    });
    renderPage();

    const expected = new Date('2026-08-10T09:00:00Z').toLocaleTimeString(
      undefined,
      { hour: '2-digit', minute: '2-digit', second: '2-digit' }
    );
    expect(await screen.findByText(new RegExp(expected))).toBeInTheDocument();
  });

  it('does not double-apply the zone when the string already carries one', async () => {
    listMock.mockResolvedValue({
      entries: [entry({ issued_at: '2026-08-10T09:00:00Z' })],
      total: 1,
      agents: ['agent-alpha'],
    });
    renderPage();

    const expected = new Date('2026-08-10T09:00:00Z').toLocaleTimeString(
      undefined,
      { hour: '2-digit', minute: '2-digit', second: '2-digit' }
    );
    expect(await screen.findByText(new RegExp(expected))).toBeInTheDocument();
  });
});

describe('changing a filter returns to the first page', () => {
  // Page state that survives a filter change is the audit-surface failure that
  // looks like good news. You are on page 4 of an unfiltered trail, you filter to
  // one agent whose history fits on one page, and the request goes out with
  // offset=150. The table comes back empty and the page says "No credential
  // access matches this filter", so the reader concludes that agent never spent
  // a credential. The rows exist; nobody asked for them.
  it('resets the offset so a narrower filter cannot read as an empty trail', async () => {
    const user = userEvent.setup();
    listMock.mockResolvedValue({
      entries: [entry()],
      total: 500, // enough for pagination to appear
      agents: ['agent-alpha', 'agent-beta'],
    });
    renderPage();
    await screen.findByText('Stripe prod');

    await user.click(screen.getByTitle('Next page'));
    await waitFor(() =>
      expect(listMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ offset: 50 })
      )
    );

    // Two unlabelled selects sit side by side (agent, then event). Pick the one
    // that actually offers the option, rather than trusting the DOM order.
    const agentSelect = screen
      .getAllByRole('combobox')
      .find((s) =>
        Array.from(s.querySelectorAll('option')).some(
          (o) => o.getAttribute('value') === 'agent-beta'
        )
      );
    expect(agentSelect).toBeDefined();
    await user.selectOptions(agentSelect!, 'agent-beta');

    await waitFor(() =>
      expect(listMock).toHaveBeenLastCalledWith(
        expect.objectContaining({ agent_id: 'agent-beta', offset: 0 })
      )
    );
  });
});

describe('an empty trail says so in a way that cannot be read as broken', () => {
  // A blank audit page is indistinguishable from a page that failed to load, and
  // on a fresh instance blank is the CORRECT state. It has to say which.
  it('distinguishes "nothing recorded yet" from "nothing matches this filter"', async () => {
    listMock.mockResolvedValue({ entries: [], total: 0, agents: [] });
    renderPage();
    expect(
      await screen.findByText(/No credential access recorded yet/)
    ).toBeInTheDocument();
  });
});
