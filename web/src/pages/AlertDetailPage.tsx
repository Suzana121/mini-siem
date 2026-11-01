import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { NormalizedEvent, Status } from "../api/types";
import { hasRole, useAuth } from "../auth/auth";
import { ErrorNote, MitreChips, SeverityBadge, StatusBadge, formatTime } from "../components/ui";

type Tab = "overview" | "events";

function EventsTable({ events }: { events: NormalizedEvent[] }) {
  if (events.length === 0) return <p>No related events found.</p>;
  return (
    <div className="table-wrap">
      <table>
        <caption className="sr-only">Related events</caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Action</th>
            <th scope="col">Outcome</th>
            <th scope="col">User</th>
            <th scope="col">Source</th>
            <th scope="col">Host</th>
            <th scope="col">Raw</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={`${e.timestamp}-${i}`}>
              <td>{formatTime(e.timestamp)}</td>
              <td>{e.event.action}</td>
              <td>{e.event.outcome}</td>
              <td>{e.user.name ?? "—"}</td>
              <td>{e.source.ip ?? "—"}</td>
              <td>{e.host.name ?? "—"}</td>
              <td className="raw-cell">
                <code className="raw">{e.raw}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AlertDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("overview");

  const alert = useQuery({ queryKey: ["alert", id], queryFn: () => api.alert(id) });
  const events = useQuery({
    queryKey: ["alert-events", id],
    queryFn: () => api.alertEvents(id),
    enabled: tab === "events",
  });
  const mutation = useMutation({
    mutationFn: (status: Status) => api.setStatus(id, status),
    onSuccess: (updated) => {
      qc.setQueryData(["alert", id], updated);
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: ["summary"] });
    },
  });

  if (alert.isLoading) return <p role="status">Loading…</p>;
  if (alert.error instanceof ApiError && alert.error.status === 404) return <p>Alert not found.</p>;
  if (alert.error || !alert.data) return <ErrorNote error={alert.error} />;
  const a = alert.data;
  const canTriage = hasRole(user, "analyst");

  return (
    <article aria-labelledby="alert-h">
      <p>
        <Link to="/alerts">← Back to alerts</Link>
      </p>
      <h1 id="alert-h">{a.title}</h1>
      <div className="row">
        <SeverityBadge severity={a.severity} />
        <StatusBadge status={a.status} />
        <span>Risk {a.risk_score}</span>
        <span className="muted">Rule {a.rule_id}</span>
      </div>
      <MitreChips mitre={a.mitre} />
      {canTriage && (
        <div className="row actions">
          <button
            type="button"
            disabled={a.status !== "open" || mutation.isPending}
            onClick={() => mutation.mutate("acknowledged")}
          >
            Acknowledge
          </button>
          <button
            type="button"
            disabled={a.status === "closed" || mutation.isPending}
            onClick={() => mutation.mutate("closed")}
          >
            Close
          </button>
        </div>
      )}
      <ErrorNote error={mutation.error} />

      <div role="tablist" aria-label="Alert sections" className="tabs">
        {(["overview", "events"] as Tab[]).map((t) => (
          <button
            key={t}
            role="tab"
            id={`tab-${t}`}
            type="button"
            aria-selected={tab === t}
            aria-controls={`panel-${t}`}
            tabIndex={tab === t ? 0 : -1}
            onClick={() => setTab(t)}
            onKeyDown={(e) => {
              if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
                const next = t === "overview" ? "events" : "overview";
                setTab(next);
                document.getElementById(`tab-${next}`)?.focus();
              }
            }}
          >
            {t === "overview" ? "Overview" : "Related events"}
          </button>
        ))}
      </div>

      {tab === "overview" ? (
        <div role="tabpanel" id="panel-overview" aria-labelledby="tab-overview" className="panel">
          <dl className="facts">
            <dt>First seen</dt>
            <dd>{formatTime(a.first_seen)}</dd>
            <dt>Last seen</dt>
            <dd>{formatTime(a.last_seen)}</dd>
            <dt>Events / occurrences</dt>
            <dd>
              {a.count} / {a.occurrences}
            </dd>
            <dt>Host</dt>
            <dd>{a.host ?? "—"}</dd>
            <dt>User</dt>
            <dd>
              {a.user.name ?? "—"}
              {a.user.target ? ` → ${a.user.target}` : ""}
            </dd>
            <dt>Source</dt>
            <dd>
              {a.source.ip ?? "—"}
              {a.source.port != null ? `:${a.source.port}` : ""}
              {a.source.internal ? " (internal)" : ""}
            </dd>
            <dt>Geo</dt>
            <dd>{[a.source.geo?.city, a.source.geo?.country].filter(Boolean).join(", ") || "—"}</dd>
            <dt>Threat intel</dt>
            <dd>{a.threat.listed ? `Listed in ${a.threat.feeds.join(", ") || "unknown feed"}` : "Not listed"}</dd>
          </dl>
          <h2>Risk factors</h2>
          {a.risk_factors.length ? (
            <ul>
              {a.risk_factors.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          ) : (
            <p className="muted">None recorded.</p>
          )}
          <h2>Evidence</h2>
          <pre className="evidence" tabIndex={0} aria-label="Evidence log lines">
            {a.evidence.join("\n")}
          </pre>
        </div>
      ) : (
        <div role="tabpanel" id="panel-events" aria-labelledby="tab-events" className="panel">
          {events.isLoading && <p role="status">Loading events…</p>}
          <ErrorNote error={events.error} />
          {events.data && <EventsTable events={events.data} />}
        </div>
      )}
    </article>
  );
}
