import { vi } from "vitest";
import type { Role, StoredAlert } from "../api/types";

type Handler = (req: { url: URL; method: string; body: unknown; headers: Headers }) => { status?: number; json?: unknown };

/** Test-only fetch mock: route "METHOD /path" -> handler or static JSON. */
export function mockFetch(routes: Record<string, Handler | unknown>) {
  const calls: { method: string; path: string; headers: Headers; init: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    calls.push({ method, path: url.pathname, headers, init });
    const route = routes[`${method} ${url.pathname}`];
    if (route === undefined) return new Response(JSON.stringify({ detail: "not mocked" }), { status: 404 });
    const out =
      typeof route === "function"
        ? (route as Handler)({ url, method, body: init.body ? JSON.parse(String(init.body)) : undefined, headers })
        : { json: route };
    const status = out.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(out.json ?? {}), { status });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

export const me = (role: Role) => ({ id: "u1", username: "tester", role });

export function makeAlert(over: Partial<StoredAlert> = {}): StoredAlert {
  return {
    id: "a1",
    rule_id: "ssh_bruteforce",
    title: "SSH brute force",
    severity: "high",
    mitre: [{ id: "T1110", name: "Brute Force", tactic: "Credential Access" }],
    timestamp: "2026-01-01T10:00:00Z",
    first_seen: "2026-01-01T09:55:00Z",
    last_seen: "2026-01-01T10:00:00Z",
    host: "web1",
    group: {},
    count: 5,
    evidence: ["<img src=x onerror=alert(1)> Failed password"],
    source: { ip: "203.0.113.9", port: 22, internal: false, geo: null },
    user: { name: "root", target: null },
    threat: { listed: false, feeds: [] },
    risk_score: 70,
    risk_factors: ["repeated failures"],
    dedup_key: "k",
    status: "open",
    occurrences: 1,
    ...over,
  };
}
