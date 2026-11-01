// Mirrors app/store.py::StoredAlert, app/schema.py and the stage 4 contract.

export type Role = "viewer" | "analyst" | "admin";
export type Status = "open" | "acknowledged" | "closed";
export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];
export const STATUSES: Status[] = ["open", "acknowledged", "closed"];

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface GeoInfo {
  country_iso: string | null;
  country: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
}

export interface SourceInfo {
  ip: string | null;
  port: number | null;
  internal: boolean | null;
  geo: GeoInfo | null;
}

export interface UserInfo {
  name: string | null;
  target: string | null;
}

export interface ThreatInfo {
  listed: boolean;
  feeds: string[];
}

export interface StoredAlert {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity | string;
  mitre: MitreTechnique[];
  timestamp: string;
  first_seen: string;
  last_seen: string;
  host: string | null;
  group: Record<string, unknown>;
  count: number;
  evidence: string[];
  source: SourceInfo;
  user: UserInfo;
  threat: ThreatInfo;
  risk_score: number;
  risk_factors: string[];
  dedup_key: string;
  status: Status;
  occurrences: number;
}

export interface NormalizedEvent {
  timestamp: string;
  log_source: string;
  event: { category: string; action: string; outcome: "success" | "failure" | "unknown" };
  host: { name: string | null };
  process: { name: string | null; pid: number | null };
  user: UserInfo;
  source: SourceInfo;
  threat: ThreatInfo;
  labels: Record<string, string>;
  raw: string;
}

export interface Me {
  id: string;
  username: string;
  role: Role;
}

export interface AdminUser extends Me {
  disabled: boolean;
  created_at: string;
}

export interface ApiKey {
  id: string;
  name: string;
  created_at?: string;
}

export interface CreatedApiKey extends ApiKey {
  key: string;
}

export interface StatsSummary {
  by_status: Record<Status, number>;
  by_severity: Record<Severity, number>;
  last_24h: number;
  top_source_ips: { ip: string; alerts: number; max_risk: number }[];
  top_users: { user: string; alerts: number }[];
}

export interface AttackTechniqueStat {
  id: string;
  name: string;
  alerts: number;
  max_severity: Severity | string;
}

export interface AttackStats {
  tactics: { tactic: string; techniques: AttackTechniqueStat[] }[];
}

export interface AlertFilters {
  status?: Status | "";
  severity?: Severity | "";
  q?: string;
  rule_id?: string;
  since?: string;
  limit?: number;
  offset?: number;
}
