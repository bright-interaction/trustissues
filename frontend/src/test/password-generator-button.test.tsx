import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PasswordGeneratorButton from '@/components/PasswordGeneratorButton';
import { passwordMeetsCharacterRequirements } from '@/lib/password-generator';

describe('PasswordGeneratorButton', () => {
  it('generates immediately when the value is blank', async () => {
    const onGenerate = vi.fn();
    const user = userEvent.setup();
    render(<PasswordGeneratorButton currentValue="" onGenerate={onGenerate} />);

    await user.click(screen.getByRole('button', { name: 'Generate strong password' }));

    expect(onGenerate).toHaveBeenCalledOnce();
    const generated = onGenerate.mock.calls[0][0] as string;
    expect(generated).toHaveLength(24);
    expect(passwordMeetsCharacterRequirements(generated)).toBe(true);
  });

  it('requires a second deliberate action before replacing a non-empty value', async () => {
    const onGenerate = vi.fn();
    const user = userEvent.setup();
    render(<PasswordGeneratorButton currentValue="keep-this" onGenerate={onGenerate} />);

    await user.click(screen.getByRole('button', { name: 'Generate strong password' }));

    expect(onGenerate).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('A value is already entered');

    await user.click(screen.getByRole('button', { name: 'Replace with generated password' }));
    expect(onGenerate).toHaveBeenCalledOnce();
  });

  it('lets the user cancel replacement without changing the value', async () => {
    const onGenerate = vi.fn();
    const user = userEvent.setup();
    render(<PasswordGeneratorButton currentValue="keep-this" onGenerate={onGenerate} />);

    await user.click(screen.getByRole('button', { name: 'Generate strong password' }));
    await user.click(screen.getByRole('button', { name: 'Keep current value' }));

    expect(onGenerate).not.toHaveBeenCalled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Generate strong password' })).toBeInTheDocument();
  });
});
