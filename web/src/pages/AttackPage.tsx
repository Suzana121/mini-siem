import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { AttackStats } from "../api/types";
import { ErrorNote } from "../components/ui";

/** Bucket an alert count into 0 (none) .. 4 (hottest) relative to the busiest technique. */
export function shadeLevel(count: number, max: number): 0 | 1 | 2 | 3 | 4 {
  if (count <= 0 || max <= 0) return 0;
  const ratio = count / max;
  if (ratio > 0.75) return 4;
  if (ratio > 0.5) return 3;
  if (ratio > 0.25) return 2;
  return 1;
}

export function Heatmap({ data }: { data: AttackStats }) {
  const max = Math.max(0, ...data.tactics.flatMap((t) => t.techniques.map((x) => x.alerts)));
  return (
    <div className="heatmap" role="list" aria-label="ATT&CK tactics">
      {data.tactics.map((t) => (
        <section className="tactic" role="listitem" key={t.tactic} aria-label={t.tactic}>
          <h2>{t.tactic}</h2>
          <ul>
            {t.techniques.map((x) => {
              const level = shadeLevel(x.alerts, max);
              return (
                <li key={x.id}>
                  <Link
                    to={`/alerts?technique=${encodeURIComponent(x.id)}`}
                    className="cell"
                    data-level={level}
                    aria-label={`${x.id} ${x.name}: ${x.alerts} alerts, max severity ${x.max_severity}`}
                  >
                    <span className="cell-id">{x.id}</span>
                    <span className="cell-name">{x.name}</span>
                    <span className="cell-count">{x.alerts}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}

const RANGES: [string, number][] = [
  ["Last 24 hours", 1],
  ["Last 7 days", 7],
  ["Last 30 days", 30],
];

export function AttackPage() {
  const [days, setDays] = useState(7);
  const q = useQuery({
    queryKey: ["attack", days],
    queryFn: () => api.attack(new Date(Date.now() - days * 86_400_000).toISOString()),
  });
  return (
    <>
      <h1>MITRE ATT&amp;CK coverage</h1>
      <label>
        Period{" "}
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {RANGES.map(([label, d]) => (
            <option key={d} value={d}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <ErrorNote error={q.error} />
      {q.isLoading && <p role="status">Loading…</p>}
      {q.data &&
        (q.data.tactics.length ? <Heatmap data={q.data} /> : <p>No techniques observed in this period.</p>)}
    </>
  );
}
