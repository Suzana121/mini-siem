import type { MitreTechnique } from "../api/types";

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge st-${status}`}>{status}</span>;
}

export function MitreChips({ mitre }: { mitre: MitreTechnique[] }) {
  return (
    <ul className="chips" aria-label="MITRE ATT&CK techniques">
      {mitre.map((t) => (
        <li key={t.id} className="chip" title={`${t.tactic}: ${t.name}`}>
          {t.id} {t.name}
        </li>
      ))}
    </ul>
  );
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function ErrorNote({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  return (
    <p role="alert" className="error">
      {error instanceof Error ? error.message : "Something went wrong"}
      {onDismiss && (
        <>
          {" "}
          <button type="button" onClick={onDismiss}>
            Dismiss
          </button>
        </>
      )}
    </p>
  );
}
