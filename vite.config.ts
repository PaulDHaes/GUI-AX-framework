import path from "path";
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    server: {
      port: 3000,
      host: "0.0.0.0",
      // Docker Desktop bind mounts (macOS) don't reliably forward native
      // filesystem events into the container, so host-side edits can go
      // undetected without polling — this was causing stale/no-HMR reloads.
      watch: {
        usePolling: true,
        interval: 300,
      },
    },
    plugins: [react()],
    define: {
      // API keys are consumed server-side by the bridge (/api/ai/analyze).
      // This define prevents legacy process.env references from throwing at
      // build time — the key is never actually exposed to the frontend.
      "process.env.ANTHROPIC_API_KEY": JSON.stringify(""),
    },
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "."),
      },
    },
  };
});
