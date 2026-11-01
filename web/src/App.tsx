import { NavLink, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { AuthProvider, RequireRole, hasRole, useAuth } from "./auth/auth";
import { AdminPage } from "./pages/AdminPage";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
import { AttackPage } from "./pages/AttackPage";
import { LoginPage } from "./pages/LoginPage";

function Layout() {
  const { user, signOut } = useAuth();
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <strong className="brand">mini-siem</strong>
        <nav aria-label="Main">
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/attack">ATT&amp;CK</NavLink>
          {hasRole(user, "admin") && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <span className="spacer" />
        {user && (
          <span className="who">
            {user.username} <span className="chip">{user.role}</span>
          </span>
        )}
        <button type="button" onClick={() => void signOut()}>
          Sign out
        </button>
      </header>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
    </>
  );
}

export function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <RequireRole role="viewer">
              <Layout />
            </RequireRole>
          }
        >
          <Route index element={<Navigate to="/alerts" replace />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/alerts/:id" element={<AlertDetailPage />} />
          <Route path="/attack" element={<AttackPage />} />
          <Route
            path="/admin"
            element={
              <RequireRole role="admin">
                <AdminPage />
              </RequireRole>
            }
          />
          <Route path="*" element={<p>Page not found.</p>} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
