import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { NormalizedEvent } from "../api/types";
import { makeAlert, me, mockFetch } from "./mockApi";
import { renderApp } from "./render";

afterEach(() => vi.unstubAllGlobals());

const event = (raw: string): NormalizedEvent =>
  ({
    timestamp: "2026-01-01T10:00:00Z",
    log_source: "auth.log",
    event: { category: "authentication", action: "ssh_login", outcome: "failure" },
    host: { name: "web1" },
    user: { name: "<img src=x onerror=alert(1)>", target: null },
    source: { ip: "203.0.113.9" },
    raw,
  }) as NormalizedEvent;

describe("related events tab", () => {
  it("renders raw log text as text and keeps the raw column from collapsing", async () => {
    mockFetch({
      "GET /auth/me": me("viewer"),
      "GET /alerts/a1": makeAlert(),
      "GET /alerts/a1/events": [event("Failed password for <img src=x onerror=alert(1)>")],
    });
    const { container } = renderApp("/alerts/a1");
    await userEvent.click(await screen.findByRole("tab", { name: "Related events" }));
    const raw = await screen.findByText("Failed password for <img src=x onerror=alert(1)>");
    expect(container.querySelector("img")).toBeNull();
    expect(raw.closest("td")).toHaveClass("raw-cell");
  });

  it("shows an empty state", async () => {
    mockFetch({ "GET /auth/me": me("viewer"), "GET /alerts/a1": makeAlert(), "GET /alerts/a1/events": [] });
    renderApp("/alerts/a1");
    await userEvent.click(await screen.findByRole("tab", { name: "Related events" }));
    expect(await screen.findByText("No related events found.")).toBeInTheDocument();
  });
});
