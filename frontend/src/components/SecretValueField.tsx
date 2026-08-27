import { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import PasswordGeneratorButton from '@/components/PasswordGeneratorButton';

interface SecretValueFieldProps {
  value: string;
  onChange: (value: string) => void;
  inputLabel: string;
  visibilityLabel: string;
  placeholder: string;
  required?: boolean;
}

/**
 * Password-masked value input used by both vault editors. Visibility is kept
 * only inside this component, so dismissing, locking, or successfully
 * submitting an editor unmounts the field and resets it to masked.
 */
export default function SecretValueField({
  value,
  onChange,
  inputLabel,
  visibilityLabel,
  placeholder,
  required = false,
}: SecretValueFieldProps) {
  const [visible, setVisible] = useState(false);

  return (
    <>
      <div className="flex items-stretch gap-2">
        <input
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          aria-label={inputLabel}
          autoComplete="new-password"
          autoCapitalize="none"
          spellCheck={false}
          placeholder={placeholder}
          required={required}
          className="min-w-0 flex-1 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-mono outline-none focus:border-slate-400"
        />
        <button
          type="button"
          onClick={() => setVisible((shown) => !shown)}
          aria-label={`${visible ? 'Hide' : 'Show'} ${visibilityLabel}`}
          aria-pressed={visible}
          className="rounded-lg border border-slate-200 bg-white px-2.5 text-slate-500 hover:bg-slate-50 hover:text-slate-700"
        >
          {visible ? (
            <EyeOff className="h-4 w-4" aria-hidden="true" />
          ) : (
            <Eye className="h-4 w-4" aria-hidden="true" />
          )}
        </button>
      </div>
      <PasswordGeneratorButton currentValue={value} onGenerate={onChange} />
    </>
  );
}
