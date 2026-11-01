import React from 'react';
import { CheckCircle2, Info, XCircle } from 'lucide-react';

const TONES = {
  success: { cls: 'border-[#bce5bc] bg-surface-raised text-[#09660a]', Icon: CheckCircle2 },
  error: { cls: 'border-[#f0c2c2] bg-surface-raised text-[#8f2727]', Icon: XCircle },
  info: { cls: 'border-brand-200 bg-surface-raised text-brand-800', Icon: Info },
};

function Toast({ message, type = 'success' }) {
  const { cls, Icon } = TONES[type] || TONES.info;

  return (
    <div
      role="status"
      aria-live="polite"
      className={`fixed right-5 top-20 z-50 flex max-w-sm animate-fade-up items-start gap-3
                  rounded-xl border px-4 py-3 shadow-card ${cls}`}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <p className="text-sm font-medium">{message}</p>
    </div>
  );
}

export default Toast;
