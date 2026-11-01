import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { CreatedApiKey, Role } from "../api/types";
import { ErrorNote, formatTime } from "../components/ui";

const ROLES: Role[] = ["viewer", "analyst", "admin"];

function Users() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: api.users });
  const refresh = () => qc.invalidateQueries({ queryKey: ["users"] });
  const update = useMutation({
    mutationFn: (v: { id: string; role?: Role; disabled?: boolean }) => api.updateUser(v.id, v),
    onSuccess: refresh,
  });
  const create = useMutation({ mutationFn: api.createUser, onSuccess: refresh });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  function onCreate(e: FormEvent) {
    e.preventDefault();
    create.mutate(
      { username: username.trim().toLowerCase(), password, role },
      {
        onSuccess: () => {
          setUsername("");
          setPassword("");
        },
      },
    );
  }

  return (
    <section aria-labelledby="users-h">
      <h2 id="users-h">Users</h2>
      <ErrorNote error={users.error ?? update.error} />
      <div className="table-wrap">
        <table>
          <caption className="sr-only">Users</caption>
          <thead>
            <tr>
              <th scope="col">Username</th>
              <th scope="col">Role</th>
              <th scope="col">Status</th>
              <th scope="col">Created</th>
            </tr>
          </thead>
          <tbody>
            {users.data?.map((u) => (
              <tr key={u.id}>
                <th scope="row">{u.username}</th>
                <td>
                  <select
                    aria-label={`Role for ${u.username}`}
                    value={u.role}
                    onChange={(e) => update.mutate({ id: u.id, role: e.target.value as Role })}
                  >
                    {ROLES.map((r) => (
                      <option key={r}>{r}</option>
                    ))}
                  </select>
                </td>
                <td>
                  <button type="button" onClick={() => update.mutate({ id: u.id, disabled: !u.disabled })}>
                    {u.disabled ? "Enable" : "Disable"} <span className="sr-only">{u.username}</span>
                  </button>{" "}
                  {u.disabled ? "disabled" : "active"}
                </td>
                <td>{formatTime(u.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <form onSubmit={onCreate} className="filters" aria-label="Create user">
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" />
        </label>
        <label>
          Password (min 12 characters)
          <input
            type="password"
            value={password}
            minLength={12}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="new-password"
          />
        </label>
        <label>
          Role
          <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </label>
        <button type="submit" className="primary" disabled={create.isPending}>
          Create user
        </button>
      </form>
      <ErrorNote error={create.error} />
    </section>
  );
}

function ApiKeys() {
  const qc = useQueryClient();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: api.apiKeys });
  const [name, setName] = useState("");
  // The secret lives only in component state; it is never cached or persisted.
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  const create = useMutation({
    mutationFn: api.createApiKey,
    onSuccess: (k) => {
      setCreated(k);
      setName("");
      void qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
  const remove = useMutation({
    mutationFn: api.deleteApiKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  return (
    <section aria-labelledby="keys-h">
      <h2 id="keys-h">API keys</h2>
      <p className="muted">Ingest-only keys for log shippers.</p>
      {created && (
        <div role="status" className="card key-once">
          <p>
            Key <strong>{created.name}</strong> created. Copy it now; it will not be shown again.
          </p>
          <code className="raw" data-testid="new-key">
            {created.key}
          </code>{" "}
          <button type="button" onClick={() => void navigator.clipboard?.writeText(created.key)}>
            Copy
          </button>{" "}
          <button type="button" onClick={() => setCreated(null)}>
            Done
          </button>
        </div>
      )}
      <ErrorNote error={keys.error ?? remove.error} />
      <ul className="plain">
        {keys.data?.map((k) => (
          <li key={k.id} className="row">
            <span>{k.name}</span>
            <button
              type="button"
              onClick={() => {
                if (window.confirm(`Revoke API key "${k.name}"?`)) remove.mutate(k.id);
              }}
            >
              Revoke <span className="sr-only">{k.name}</span>
            </button>
          </li>
        ))}
        {keys.data?.length === 0 && <li className="muted">No API keys.</li>}
      </ul>
      <form
        className="filters"
        aria-label="Create API key"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate(name.trim());
        }}
      >
        <label>
          Key name
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <button type="submit" className="primary" disabled={create.isPending}>
          Create key
        </button>
      </form>
      <ErrorNote error={create.error} />
    </section>
  );
}

export function AdminPage() {
  return (
    <>
      <h1>Administration</h1>
      <Users />
      <ApiKeys />
    </>
  );
}
