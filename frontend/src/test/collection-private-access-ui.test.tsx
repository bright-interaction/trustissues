import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import CollectionPrivateAccessPolicyField, {
  CollectionAccessBadge,
} from '@/components/CollectionPrivateAccessPolicyField';
import type { CollectionPrivateAccessPolicy } from '@/lib/types';

function PolicyHarness({
  initial,
  canSelectProtected,
}: {
  initial?: CollectionPrivateAccessPolicy;
  canSelectProtected?: boolean;
}) {
  const [policy, setPolicy] = useState<CollectionPrivateAccessPolicy | undefined>(initial);
  return (
    <CollectionPrivateAccessPolicyField
      value={policy}
      onChange={setPolicy}
      canSelectProtected={canSelectProtected}
    />
  );
}

describe('collection private-access controls', () => {
  it('defaults missing legacy policy data to standard and explains every choice', () => {
    render(<PolicyHarness />);

    expect(screen.getByRole('radio', { name: /standard access/i })).toBeChecked();
    expect(screen.getByText(/client collections that must work without/i)).toBeInTheDocument();
    expect(screen.getByText(/metadata stays visible normally/i)).toBeInTheDocument();
    expect(screen.getByText(/collection and its entries are hidden/i)).toBeInTheDocument();
    expect(screen.getByRole('note')).toHaveTextContent(/does not replace sign-in, MFA/i);
  });

  it('warns before choosing a policy that depends on the private URL', async () => {
    const user = userEvent.setup();
    render(<PolicyHarness initial="standard" />);

    await user.click(screen.getByRole('radio', { name: /private for all access/i }));

    expect(screen.getByRole('radio', { name: /private for all access/i })).toBeChecked();
    expect(screen.getByRole('note')).toHaveTextContent(/configure and test the private URL first/i);
    expect(screen.getByRole('note')).toHaveTextContent(/may disappear from the normal URL/i);
  });

  it('shows compact badges only for protected collections', () => {
    const { rerender } = render(<CollectionAccessBadge policy="sensitive_private" />);
    expect(screen.getByText('Private actions')).toBeInTheDocument();

    rerender(<CollectionAccessBadge policy="fully_private" />);
    expect(screen.getByText('Private only')).toBeInTheDocument();

    rerender(<CollectionAccessBadge policy={undefined} />);
    expect(screen.queryByText('Private only')).not.toBeInTheDocument();
  });

  it('keeps standard client collections usable but disables protected choices until private ingress is verified', () => {
    render(<PolicyHarness initial="standard" canSelectProtected={false} />);

    expect(screen.getByRole('radio', { name: /standard access/i })).toBeEnabled();
    expect(screen.getByRole('radio', { name: /private for secret actions/i })).toBeDisabled();
    expect(screen.getByRole('radio', { name: /private for all access/i })).toBeDisabled();
    expect(screen.getByRole('note')).toHaveTextContent(/only on the private TrustIssues URL/i);
    expect(screen.getByRole('note')).toHaveTextContent(/standard client collections remain available here/i);
  });
});
