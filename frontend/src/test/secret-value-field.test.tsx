import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SecretValueField from '@/components/SecretValueField';

function Harness() {
  const [mounted, setMounted] = useState(true);
  const [value, setValue] = useState('already-secret');

  return (
    <>
      <button type="button" onClick={() => setMounted((current) => !current)}>
        {mounted ? 'Close editor' : 'Open editor'}
      </button>
      {mounted && (
        <SecretValueField
          value={value}
          onChange={setValue}
          inputLabel="Secret value"
          visibilityLabel="secret value"
          placeholder="Secret value"
        />
      )}
    </>
  );
}

describe('SecretValueField', () => {
  it('masks by default, reveals deliberately, and masks again after the editor remounts', async () => {
    const user = userEvent.setup();
    render(<Harness />);

    expect(screen.getByLabelText('Secret value')).toHaveAttribute('type', 'password');

    await user.click(screen.getByRole('button', { name: 'Show secret value' }));
    expect(screen.getByLabelText('Secret value')).toHaveAttribute('type', 'text');
    expect(screen.getByRole('button', { name: 'Hide secret value' })).toHaveAttribute(
      'aria-pressed',
      'true'
    );

    await user.click(screen.getByRole('button', { name: 'Close editor' }));
    expect(screen.queryByLabelText('Secret value')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open editor' }));

    expect(screen.getByLabelText('Secret value')).toHaveAttribute('type', 'password');
    expect(screen.getByRole('button', { name: 'Show secret value' })).toHaveAttribute(
      'aria-pressed',
      'false'
    );
  });
});
