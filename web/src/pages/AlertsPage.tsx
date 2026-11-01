import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { SEVERITIES, STATUSES, type StoredAlert } from "../api/types";
import { ErrorNote, MitreChips, SeverityBadge, StatusBadge, formatTime } from "../components/ui";

export const REFRESH_MS = 5000;

export function Kpis() {
  const q = useQuery({ queryKey: ["summary"], queryFn: api.summary, refetchInterval: REFRESH_MS });
  const s = q.data;
  const items: [string, number | undefined][] = [
    ["Open", s?.by_status.open],
    ["Acknowledged", s?.by_status.acknowledged],
    ["Critical", s?.by_severity.critical],
    ["High", s?.by_severity.high],
    ["Last 24h", s?.last_24h],
  ];
  return (
    <section aria-label="Key figures" className="kpis">
      {items.map(([label, value]) => (
        <div className="kpi" key={label}>
          <span className="kpi-value">{value ?? "—"}</span>
          <span className="kpi-label">{label}</span>
        </div>
      ))}
      <ErrorNote error={q.error} />
    </section>
  );
}

export function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const severity = params.get("severity") ?? "";
  const q = params.get("q") ?? "";
  const technique = params.get("technique") ?? "";

  const alerts = useQuery({
    queryKey: ["alerts", { status, severity, q }],
    queryFn: () =>
      api.alerts({ status: status as never, severity: severity as never, q }),
    refetchInterval: REFRESH_MS,
  });

  function set(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  const rows: StoredAlert[] = (alerts.data ?? [])
    .filter((a) => !technique || a.mitre.some((m) => m.id === technique))
    .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));

  return (
    <>
      <h1>Alerts</h1>
      <Kpis />
      <form className="filters" role="search" aria-label="Filter alerts" onSubmit={(e) => e.preventDefault()}>
        <label>
          Status
          <select value={status} onChange={(e) => set("status", e.target.value)}>
            <option value="">All</option>
            {STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label>
          Severity
          <select value={severity} onChange={(e) => set("severity", e.target.value)}>
            <option value="">All</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className="grow">
          Search
          <input
            type="search"
            value={q}
            placeholder="IP, user, host or rule"
            onChange={(e) => set("q", e.target.value)}
          />
        </label>
        {technique && (
          <span className="chip">
            Technique {technique}{" "}
            <button type="button" aria-label={`Clear technique filter ${technique}`} onClick={() => set("technique", "")}>
              ×
            </button>
          </span>
        )}
      </form>
      <ErrorNote error={alerts.error} />
      <div className="table-wrap">
        <table>
          <caption className="sr-only">Alerts, most recently seen first</caption>
          <thead>
            <tr>
              <th scope="col">Severity</th>
              <th scope="col">Risk</th>
              <th scope="col">Alert</th>
              <th scope="col">Source</th>
              <th scope="col">User</th>
              <th scope="col">Host</th>
              <th scope="col">Status</th>
              <th scope="col">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td>
                  <SeverityBadge severity={a.severity} />
                </td>
                <td>{a.risk_score}</td>
                <td>
                  <Link to={`/alerts/${a.id}`}>{a.title}</Link>
                  <MitreChips mitre={a.mitre} />
                </td>
                <td>{a.source.ip ?? "—"}</td>
                <td>{a.user.name ?? "—"}</td>
                <td>{a.host ?? "—"}</td>
                <td>
                  <StatusBadge status={a.status} />
                </td>
                <td>
                  <time dateTime={a.last_seen}>{formatTime(a.last_seen)}</time>
                  {a.occurrences > 1 && <span className="muted"> ×{a.occurrences}</span>}
                </td>
              </tr>
            ))}
            {!alerts.isLoading && rows.length === 0 && (
              <tr>
                <td colSpan={8}>No alerts match.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="muted" aria-live="polite">
        {alerts.isFetching ? "Refreshing…" : "Auto-refreshes every 5 seconds."}
      </p>
    </>
  );
}
