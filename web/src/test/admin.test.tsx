import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { me, mockFetch } from "./mockApi";
import { renderApp } from "./render";

afterEach(() => vi.unstubAllGlobals());

const user = { id: "u2", username: "bob", role: "viewer", disabled: false, created_at: "2026-01-01T00:00:00Z" };

describe("admin page", () => {
  it("PATCHes only the changed fields, not the user id", async () => {
    const { calls } = mockFetch({
      "GET /auth/me": me("admin"),
      "GET /users": [user],
      "GET /api-keys": [],
      "PATCH /users/u2": { ...user, role: "analyst" },
    });
    renderApp("/admin");
    await userEvent.selectOptions(await screen.findByLabelText("Role for bob"), "analyst");
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const patch = calls.find((c) => c.method === "PATCH")!;
    expect(JSON.parse(String(patch.init.body))).toEqual({ role: "analyst" });

    await userEvent.click(await screen.findByRole("button", { name: /disable bob/i }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2));
    expect(JSON.parse(String(calls.filter((c) => c.method === "PATCH")[1].init.body))).toEqual({ disabled: true });
  });

  it("resets a user's password with only the password in the PATCH body", async () => {
    const { calls } = mockFetch({
      "GET /auth/me": me("admin"),
      "GET /users": [user],
      "GET /api-keys": [],
      "PATCH /users/u2": user,
    });
    renderApp("/admin");
    await userEvent.click(await screen.findByRole("button", { name: /reset password bob/i }));
    await userEvent.type(screen.getByLabelText(/new password for bob/i), "a-new-long-passphrase");
    await userEvent.click(screen.getByRole("button", { name: /set password/i }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(JSON.parse(String(calls.find((c) => c.method === "PATCH")!.init.body))).toEqual({
      password: "a-new-long-passphrase",
    });
    expect(await screen.findByText(/password updated/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/new password for bob/i)).not.toBeInTheDocument();
  });

  it("lets the admin dismiss a stale update error", async () => {
    mockFetch({
      "GET /auth/me": me("admin"),
      "GET /users": [{ ...user, role: "admin" }],
      "GET /api-keys": [],
      "PATCH /users/u2": () => ({ status: 409, json: { detail: "cannot remove the last admin" } }),
    });
    renderApp("/admin");
    await userEvent.selectOptions(await screen.findByLabelText("Role for bob"), "viewer");
    expect(await screen.findByText(/cannot remove the last admin/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    await waitFor(() => expect(screen.queryByText(/cannot remove the last admin/)).not.toBeInTheDocument());
  });

  it("shows the last-admin 409 message", async () => {
    mockFetch({
      "GET /auth/me": me("admin"),
      "GET /users": [{ ...user, role: "admin" }],
      "GET /api-keys": [],
      "PATCH /users/u2": () => ({ status: 409, json: { detail: "cannot remove the last admin" } }),
    });
    renderApp("/admin");
    await userEvent.selectOptions(await screen.findByLabelText("Role for bob"), "viewer");
    expect(await screen.findByText("cannot remove the last admin")).toBeInTheDocument();
  });
});

describe("api client errors", () => {
  it("turns FastAPI validation arrays into readable text", async () => {
    mockFetch({
      "POST /users": () => ({
        status: 422,
        json: { detail: [{ type: "string_too_short", loc: ["body", "password"], msg: "String should have at least 12 characters" }] },
      }),
    });
    await expect(api.createUser({ username: "x", password: "y", role: "viewer" })).rejects.toMatchObject({
      status: 422,
      message: "String should have at least 12 characters",
    });
  });
});
