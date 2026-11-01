/// <reference types="vitest" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const target = process.env.VITE_API_TARGET ?? "http://localhost:8000";
const apiPaths = ["/auth", "/users", "/api-keys", "/alerts", "/events", "/stats", "/rules", "/sources", "/health", "/ingest"];

export default defineConfig({
  plugins: [react()],
  server: {
    // Only proxy API calls; browser navigations (Accept: text/html) get the SPA.
    proxy: Object.fromEntries(
      apiPaths.map((p) => [
        p,
        {
          target,
          changeOrigin: false,
          bypass: (req: { headers: Record<string, string | string[] | undefined> }) =>
            String(req.headers.accept ?? "").includes("text/html") ? "/index.html" : undefined,
        },
      ]),
    ),
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
