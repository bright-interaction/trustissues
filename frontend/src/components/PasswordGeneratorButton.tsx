import { useEffect, useId, useState } from 'react';
import { generateStrongPassword } from '@/lib/password-generator';

interface PasswordGeneratorButtonProps {
  currentValue: string;
  onGenerate: (password: string) => void;
}

/**
 * A local-only generator control shared by add and edit forms. Existing input
 * is protected by a two-step replacement flow instead of a browser confirm,
 * which keeps the warning visible and keyboard/screen-reader accessible.
 */
export default function PasswordGeneratorButton({
  currentValue,
  onGenerate,
}: PasswordGeneratorButtonProps) {
  const [confirmReplacement, setConfirmReplacement] = useState(false);
  const [generationError, setGenerationError] = useState('');
  const helpId = useId();
  const warningId = useId();

  useEffect(() => {
    setConfirmReplacement(false);
    setGenerationError('');
  }, [currentValue]);

  function generate() {
    if (currentValue.length > 0 && !confirmReplacement) {
      setConfirmReplacement(true);
      setGenerationError('');
      return;
    }

    try {
      onGenerate(generateStrongPassword());
      setConfirmReplacement(false);
      setGenerationError('');
    } catch {
      // Fail closed. There is deliberately no Math.random fallback.
      setConfirmReplacement(false);
      setGenerationError('Secure password generation is unavailable in this browser.');
    }
  }

  const describedBy = [helpId, confirmReplacement ? warningId : '', generationError ? warningId : '']
    .filter(Boolean)
    .join(' ');

  return (
    <div className="mt-2">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={generate}
          aria-describedby={describedBy}
          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
        >
          {confirmReplacement ? 'Replace with generated password' : 'Generate strong password'}
        </button>
        {confirmReplacement && (
          <button
            type="button"
            onClick={() => setConfirmReplacement(false)}
            className="px-2 py-1.5 text-xs font-medium text-slate-500 hover:text-slate-700"
          >
            Keep current value
          </button>
        )}
      </div>
      <p id={helpId} className="mt-1 text-xs text-slate-500">
        Creates a 24-character password locally using your browser&apos;s secure random generator.
      </p>
      {confirmReplacement && (
        <p id={warningId} role="alert" className="mt-1 text-xs font-medium text-amber-700">
          A value is already entered. Choose Replace to overwrite it.
        </p>
      )}
      {generationError && (
        <p id={warningId} role="alert" className="mt-1 text-xs font-medium text-red-600">
          {generationError}
        </p>
      )}
    </div>
  );
}
