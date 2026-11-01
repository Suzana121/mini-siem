import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, setUnauthorizedHandler } from "../api/client";
import { mockFetch } from "./mockApi";

afterEach(() => {
  vi.unstubAllGlobals();
  setUnauthorizedHandler(null);
});

describe("api client", () => {
  it("sends CSRF header and same-origin credentials", async () => {
    const { calls } = mockFetch({ "PATCH /alerts/a1": { id: "a1" } });
    await api.setStatus("a1", "closed");
    expect(calls[0].headers.get("X-Requested-With")).toBe("mini-siem");
    expect(calls[0].init.credentials).toBe("same-origin");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ status: "closed" });
  });

  it("builds query strings, skipping empty values", async () => {
    const { fn } = mockFetch({ "GET /alerts": [] });
    await api.alerts({ status: "open", severity: "", q: "1.2.3.4" });
    expect(String(fn.mock.calls[0][0])).toBe("/alerts?status=open&q=1.2.3.4&limit=200");
  });

  it("invokes the unauthorized handler on 401 and throws ApiError", async () => {
    mockFetch({ "GET /alerts": () => ({ status: 401, json: { detail: "no" } }) });
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    await expect(api.alerts()).rejects.toMatchObject({ status: 401, message: "no" });
    expect(handler).toHaveBeenCalledOnce();
  });

  it("does not redirect for login/me 401s", async () => {
    mockFetch({ "POST /auth/login": () => ({ status: 401 }), "GET /auth/me": () => ({ status: 401 }) });
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    await expect(api.login("a", "b")).rejects.toBeInstanceOf(ApiError);
    await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    expect(handler).not.toHaveBeenCalled();
  });

  it("handles 204", async () => {
    mockFetch({ "POST /auth/logout": () => ({ status: 204 }) });
    await expect(api.logout()).resolves.toBeUndefined();
  });
});
