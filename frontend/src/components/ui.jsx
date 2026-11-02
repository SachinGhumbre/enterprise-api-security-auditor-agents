import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Info,
  Loader2,
  ShieldAlert,
  XCircle,
} from 'lucide-react';

/* --- Status primitives ------------------------------------------------------
 * Status colours are fixed and never reused as a series colour. Each one ships
 * with an icon AND a text label, so the hue never carries the meaning alone -
 * required because warning and serious fall below 3:1 on a light surface.
 */

export function Spinner({ className = 'h-4 w-4' }) {
  return <Loader2 className={`${className} animate-spin`} aria-hidden="true" />;
}

const SEVERITY_CHIP = {
  critical: 'chip-critical',
  high: 'chip-serious',
  medium: 'chip-warning',
  low: 'chip-info',
};

export function SeverityBadge({ severity }) {
  const key = String(severity || 'medium').toLowerCase();
  return (
    <span className={SEVERITY_CHIP[key] || SEVERITY_CHIP.medium}>
      <ShieldAlert className="h-3 w-3" aria-hidden="true" />
      {String(severity || 'Medium')}
    </span>
  );
}

const VERIFICATION_CHIP = {
  verified: 'chip-good',
  unverified: 'chip-warning',
  contradictory: 'chip-critical',
};

const VERIFICATION_ICON = {
  verified: CheckCircle2,
  unverified: AlertTriangle,
  contradictory: XCircle,
};

const VERIFICATION_LABEL = {
  verified: 'Verified',
  unverified: 'Unverified',
  contradictory: 'Contradictory',
};

export function VerificationBadge({ status }) {
  const key = String(status || '').toLowerCase();
  const Icon = VERIFICATION_ICON[key] || Info;
  return (
    <span className={VERIFICATION_CHIP[key] || 'chip-info'}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      {VERIFICATION_LABEL[key] || 'Unknown'}
    </span>
  );
}

export function ComplianceBadge({ comply }) {
  return comply ? (
    <span className="chip-good">
      <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
      Compliant
    </span>
  ) : (
    <span className="chip-critical">
      <XCircle className="h-3 w-3" aria-hidden="true" />
      Non-compliant
    </span>
  );
}

export function StatusDot({ state, label }) {
  const tone =
    state === 'ok'
      ? 'bg-status-good'
      : state === 'warn'
      ? 'bg-status-warning'
      : state === 'bad'
      ? 'bg-status-critical'
      : 'bg-ink-hairline';
  return (
    <span className="inline-flex items-center gap-2 text-sm text-ink-secondary">
      <span className={`h-2.5 w-2.5 rounded-full ${tone}`} aria-hidden="true" />
      {label}
    </span>
  );
}

/* --- Layout primitives ------------------------------------------------------ */

export function StatTile({ label, value, hint, tone = 'default', icon: Icon }) {
  // The number is the mark. Text tokens carry the value; tone is a restrained
  // accent, never a full-bleed fill that would compete across a KPI row.
  const tones = {
    default: 'text-ink-primary',
    good: 'text-[#09660a]',
    bad: 'text-[#8f2727]',
    warn: 'text-[#845a06]',
    brand: 'text-brand-700',
  };
  return (
    <div className="card animate-fade-up p-5">
      <div className="flex items-start justify-between gap-3">
        <p className="text-xs font-semibold uppercase tracking-wider text-ink-muted">{label}</p>
        {Icon ? <Icon className="h-4 w-4 shrink-0 text-brand-400" aria-hidden="true" /> : null}
      </div>
      <p className={`mt-2 text-3xl font-bold tabular-nums ${tones[tone] || tones.default}`}>
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-ink-muted">{hint}</p> : null}
    </div>
  );
}

export function Card({ title, subtitle, actions, children, className = '' }) {
  return (
    <section className={`card animate-fade-up ${className}`}>
      {(title || actions) && (
        <header className="card-header">
          <div>
            {title ? (
              <h3 className="text-base font-semibold text-ink-primary">{title}</h3>
            ) : null}
            {subtitle ? <p className="mt-0.5 text-sm text-ink-secondary">{subtitle}</p> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Banner({ tone = 'info', title, children }) {
  const map = {
    info: { cls: 'border-brand-200 bg-brand-50 text-brand-900', Icon: Info },
    warn: { cls: 'border-[#f6e2b0] bg-[#fef6e3] text-[#845a06]', Icon: AlertTriangle },
    error: { cls: 'border-[#f0c2c2] bg-[#fbeaea] text-[#8f2727]', Icon: XCircle },
    success: { cls: 'border-[#bce5bc] bg-[#e7f6e7] text-[#09660a]', Icon: CheckCircle2 },
  };
  const { cls, Icon } = map[tone] || map.info;

  return (
    <div className={`animate-fade-up rounded-xl border px-4 py-3 ${cls}`} role="status">
      <div className="flex gap-3">
        <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        <div className="min-w-0 text-sm">
          {title ? <p className="font-semibold">{title}</p> : null}
          {children ? <div className={title ? 'mt-1' : ''}>{children}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-brand-200 bg-surface-sunken px-6 py-12 text-center">
      {Icon ? <Icon className="h-8 w-8 text-brand-300" aria-hidden="true" /> : null}
      <p className="mt-3 text-sm font-semibold text-ink-primary">{title}</p>
      {children ? <p className="mt-1 max-w-md text-sm text-ink-secondary">{children}</p> : null}
    </div>
  );
}

export function Collapsible({ summary, children, defaultOpen = false }) {
  const [open, setOpen] = React.useState(defaultOpen);
  return (
    <div className="rounded-lg border border-ink-hairline">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left text-sm font-medium text-ink-secondary hover:bg-brand-50"
      >
        {summary}
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-ink-muted transition-transform ${open ? 'rotate-180' : ''}`}
          aria-hidden="true"
        />
      </button>
      {open ? <div className="border-t border-ink-hairline px-4 py-3">{children}</div> : null}
    </div>
  );
}

export function MultiSelect({
  options = [],
  selected = [],
  onChange,
  placeholder = 'Select…',
  disabled = false,
  emptyHint = 'No options available.',
  ariaLabel,
}) {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef(null);

  React.useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open ]);

  const toggle = (opt) =>
    onChange(
      selected.includes(opt) ? selected.filter((s) => s !== opt) : [...selected, opt]
    );
  const all = options.length > 0 && selected.length === options.length;
  const label =
    selected.length === 0
      ? placeholder
      : selected.length === 1
        ? selected[0]
        : `${selected.length} selected`;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-label={ariaLabel}
        className="field flex w-full items-center justify-between gap-2 text-left disabled:cursor-not-allowed disabled:opacity-60"
      >
        <span className={`truncate ${selected.length ? '' : 'text-ink-muted'}`}>{label}</span>
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-ink-muted transition-transform ${open ? 'rotate-180' : ''}`}
          aria-hidden="true"
        />
      </button>
      {open && !disabled ? (
        <div className="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-lg border border-ink-hairline bg-surface-raised p-1 shadow-raised">
          {options.length === 0 ? (
            <p className="px-3 py-2 text-sm text-ink-muted">{emptyHint}</p>
          ) : (
            <>
              <button
                type="button"
                onClick={() => onChange(all ? [] : [...options])}
                className="w-full rounded-md px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-brand-700 hover:bg-brand-50"
              >
                {all ? 'Clear all' : 'Select all'}
              </button>
              {options.map((opt) => {
                const active = selected.includes(opt);
                return (
                  <label
                    key={opt}
                    className="flex cursor-pointer items-center gap-2.5 rounded-md px-3 py-2 text-sm text-ink-secondary hover:bg-brand-50"
                  >
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={() => toggle(opt)}
                      className="h-4 w-4 shrink-0 accent-brand-600"
                    />
                    <span className="truncate">{opt}</span>
                    {active ? (
                      <CheckCircle2 className="ml-auto h-4 w-4 shrink-0 text-brand-600" aria-hidden="true" />
                    ) : null}
                  </label>
                );
              })}
            </>
          )}
        </div>
      ) : null}
    </div>
  );
}

export function ProgressBar({ value, tone = 'brand' }) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0));
  const tones = {
    brand: 'bg-brand-500',
    good: 'bg-status-good',
    warn: 'bg-status-warning',
    bad: 'bg-status-critical',
  };
  return (
    <div
      className="h-2 w-full overflow-hidden rounded-full bg-brand-100"
      role="progressbar"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      {/* 4px rounded data-end, anchored to the track start. */}
      <div
        className={`h-full rounded-full transition-all duration-500 ${tones[tone] || tones.brand}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
