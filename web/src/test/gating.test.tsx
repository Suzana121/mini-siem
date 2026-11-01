import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { makeAlert, me, mockFetch } from "./mockApi";
import { renderApp } from "./render";

afterEach(() => vi.unstubAllGlobals());

const summary = {
  by_status: { open: 3, acknowledged: 1, closed: 0 },
  by_severity: { low: 0, medium: 1, high: 2, critical: 1 },
  last_24h: 4,
  top_source_ips: [],
  top_users: [],
};

function routes(role: "viewer" | "analyst" | "admin") {
  return {
    "GET /auth/me": me(role),
    "GET /alerts": [makeAlert()],
    "GET /alerts/a1": makeAlert(),
    "GET /alerts/a1/events": [],
    "GET /stats/summary": summary,
    "GET /users": [],
    "GET /api-keys": [],
  };
}

describe("role gating", () => {
  it("redirects anonymous users to login", async () => {
    mockFetch({ "GET /auth/me": () => ({ status: 401 }) });
    renderApp("/alerts");
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
  });

  it("hides admin nav and denies /admin for analysts", async () => {
    mockFetch(routes("analyst"));
    renderApp("/admin");
    expect(await screen.findByRole("heading", { name: /access denied/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Admin" })).not.toBeInTheDocument();
  });

  it("shows admin page to admins", async () => {
    mockFetch(routes("admin"));
    renderApp("/admin");
    expect(await screen.findByRole("heading", { name: "Administration" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Admin" })).toBeInTheDocument();
  });

  it("hides Acknowledge/Close from viewers", async () => {
    mockFetch(routes("viewer"));
    renderApp("/alerts/a1");
    expect(await screen.findByRole("heading", { name: "SSH brute force" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Acknowledge" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Close" })).not.toBeInTheDocument();
  });

  it("lets analysts acknowledge, and renders log text as text", async () => {
    const { calls } = mockFetch({
      ...routes("analyst"),
      "PATCH /alerts/a1": () => ({ json: makeAlert({ status: "acknowledged" }) }),
    });
    renderApp("/alerts/a1");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByLabelText("Evidence log lines").textContent).toContain("<img src=x");
  });

  it("logs in and lands on alerts", async () => {
    let authed = false;
    mockFetch({
      ...routes("viewer"),
      "GET /auth/me": () => (authed ? { json: me("viewer") } : { status: 401 }),
      "POST /auth/login": () => {
        authed = true;
        return { json: { user: me("viewer") } };
      },
    });
    renderApp("/alerts");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Username"), "tester");
    await user.type(screen.getByLabelText("Password"), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Alerts" })).toBeInTheDocument();
  });
});

describe("alerts page", () => {
  it("shows KPIs and rows, filters by technique", async () => {
    mockFetch({
      ...routes("viewer"),
      "GET /alerts": [makeAlert(), makeAlert({ id: "a2", title: "Other", mitre: [] })],
    });
    renderApp("/alerts?technique=T1110");
    expect(await screen.findByRole("link", { name: "SSH brute force" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Other" })).not.toBeInTheDocument();
    expect(await screen.findByText("Last 24h")).toBeInTheDocument();
  });
});

describe("admin api keys", () => {
  it("shows a new key once", async () => {
    mockFetch({
      ...routes("admin"),
      "POST /api-keys": () => ({ json: { id: "k1", name: "shipper", key: "msk_secret123" } }),
    });
    renderApp("/admin");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Key name"), "shipper");
    await user.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByTestId("new-key")).toHaveTextContent("msk_secret123");
    await user.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByText("msk_secret123")).not.toBeInTheDocument();
  });
});
