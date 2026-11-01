import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { api, ApiError, setUnauthorizedHandler } from "../api/client";
import type { Me, Role } from "../api/types";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

export function hasRole(user: Me | null | undefined, min: Role): boolean {
  return !!user && RANK[user.role] >= RANK[min];
}

interface AuthState {
  user: Me | null;
  loading: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();

  const meQuery = useQuery({
    queryKey: ["me"],
    retry: false,
    staleTime: 60_000,
    queryFn: async () => {
      try {
        return await api.me();
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
  });

  // Any 401 after login means the session expired: drop state, go to login.
  const path = location.pathname + location.search;
  useEffect(() => {
    setUnauthorizedHandler(() => {
      qc.setQueryData(["me"], null);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
      if (window.location.pathname !== "/login") navigate("/login", { replace: true, state: { from: path } });
    });
    return () => setUnauthorizedHandler(null);
  }, [qc, navigate, path]);

  const signIn = useCallback(
    async (username: string, password: string) => {
      const { user } = await api.login(username, password);
      qc.setQueryData(["me"], user);
    },
    [qc],
  );

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      qc.setQueryData(["me"], null);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
    }
  }, [qc]);

  const value = useMemo<AuthState>(
    () => ({ user: meQuery.data ?? null, loading: meQuery.isLoading, signIn, signOut }),
    [meQuery.data, meQuery.isLoading, signIn, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

/** Gate a route by minimum role. Anonymous -> login; insufficient role -> 403 notice. */
export function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <p role="status">Loading…</p>;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  if (!hasRole(user, role)) {
    return (
      <section aria-labelledby="forbidden-h">
        <h1 id="forbidden-h">Access denied</h1>
        <p>This page requires the {role} role.</p>
      </section>
    );
  }
  return <>{children}</>;
}
