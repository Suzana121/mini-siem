import type {
  AdminUser,
  AlertFilters,
  ApiKey,
  AttackStats,
  CreatedApiKey,
  Me,
  NormalizedEvent,
  Role,
  StatsSummary,
  Status,
  StoredAlert,
} from "./types";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let unauthorizedHandler: (() => void) | null = null;

/** Called on any 401 from a request that isn't opted out (login, /auth/me). */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | undefined | null>;
  /** 401 is an expected answer (login form, session probe): don't redirect. */
  noRedirect?: boolean;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const data = await res.json();
    const detail = (data as { detail?: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (detail !== undefined) return JSON.stringify(detail);
  } catch {
    /* not JSON */
  }
  return res.statusText || `HTTP ${res.status}`;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-Requested-With": "mini-siem",
  };
  const init: RequestInit = { method: opts.method ?? "GET", credentials: "same-origin", headers };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch(buildUrl(path, opts.query), init);
  if (!res.ok) {
    if (res.status === 401 && !opts.noRedirect) unauthorizedHandler?.();
    throw new ApiError(res.status, await errorMessage(res));
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ user: Me }>("/auth/login", { method: "POST", body: { username, password }, noRedirect: true }),
  logout: () => request<void>("/auth/logout", { method: "POST", noRedirect: true }),
  me: () => request<Me>("/auth/me", { noRedirect: true }),

  alerts: (f: AlertFilters = {}) =>
    request<StoredAlert[]>("/alerts", { query: { ...f, limit: f.limit ?? 200 } }),
  alert: (id: string) => request<StoredAlert>(`/alerts/${encodeURIComponent(id)}`),
  setStatus: (id: string, status: Status) =>
    request<StoredAlert>(`/alerts/${encodeURIComponent(id)}`, { method: "PATCH", body: { status } }),
  alertEvents: (id: string) => request<NormalizedEvent[]>(`/alerts/${encodeURIComponent(id)}/events`),

  summary: () => request<StatsSummary>("/stats/summary"),
  attack: (since?: string) => request<AttackStats>("/stats/attack", { query: { since } }),

  users: () => request<AdminUser[]>("/users"),
  createUser: (body: { username: string; password: string; role: Role }) =>
    request<AdminUser>("/users", { method: "POST", body }),
  updateUser: (id: string, body: { role?: Role; disabled?: boolean; password?: string }) =>
    request<AdminUser>(`/users/${encodeURIComponent(id)}`, { method: "PATCH", body }),

  apiKeys: () => request<ApiKey[]>("/api-keys"),
  createApiKey: (name: string) => request<CreatedApiKey>("/api-keys", { method: "POST", body: { name } }),
  deleteApiKey: (id: string) => request<void>(`/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
};
