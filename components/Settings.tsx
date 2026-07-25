import React, { useState, useEffect } from "react";
import {
  Save,
  Server,
  CheckCircle,
  XCircle,
  RefreshCw,
  GitBranch,
  Package,
  AlertTriangle,
  Terminal,
  Globe,
  Plug,
  Copy,
} from "lucide-react";
import {
  getApiUrl,
  setApiUrl,
  checkConnection,
} from "../services/axiomProvider";
import { getOnlineGeoEnabled, setOnlineGeoEnabled } from "../services/prefs";

interface AxVersionInfo {
  installed: boolean;
  path: string;
  commit?: string;
  branch?: string;
  date?: string;
  module_count?: number;
}

const Settings = () => {
  const [apiUrl, setLocalApiUrl] = useState("");
  const [status, setStatus] = useState<
    "idle" | "checking" | "connected" | "error"
  >("idle");
  const [activeTab, setActiveTab] = useState<
    "connection" | "updater" | "map" | "mcp"
  >("connection");

  // ── Privacy / map preferences ───────────────────────────────────────────
  const [onlineGeo, setOnlineGeo] = useState<boolean>(getOnlineGeoEnabled());
  const toggleOnlineGeo = () => {
    const next = !onlineGeo;
    setOnlineGeo(next);
    setOnlineGeoEnabled(next);
  };

  // ── MCP server state ──────────────────────────────────────────────────────
  interface McpStatus {
    running: boolean;
    available: boolean;
    pid: number | null;
    transport: string | null;
    host: string | null;
    port: number | null;
    endpoint: string | null;
    actingAs: string | null;
    startedAt: string | null;
    logTail: string[];
  }
  const [mcp, setMcp] = useState<McpStatus | null>(null);
  const [mcpPort, setMcpPort] = useState<number>(8787);
  const [mcpBusy, setMcpBusy] = useState(false);
  const [mcpError, setMcpError] = useState<string | null>(null);

  const fetchMcpStatus = async () => {
    try {
      const res = await fetch(`${getApiUrl()}/api/mcp/status`);
      if (res.ok) {
        const data: McpStatus = await res.json();
        setMcp(data);
        if (data.port) setMcpPort(data.port);
      }
    } catch {
      setMcp(null);
    }
  };

  const toggleMcp = async () => {
    if (!mcp) return;
    setMcpBusy(true);
    setMcpError(null);
    const action = mcp.running ? "stop" : "start";
    try {
      const res = await fetch(`${getApiUrl()}/api/mcp/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          action === "start"
            ? { transport: "streamable-http", port: mcpPort }
            : {},
        ),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setMcp(data);
      if (data.port) setMcpPort(data.port);
    } catch (err: unknown) {
      setMcpError(err instanceof Error ? err.message : String(err));
    } finally {
      setMcpBusy(false);
    }
  };

  // ── Ax updater state ────────────────────────────────────────────────────
  const [axVersion, setAxVersion] = useState<AxVersionInfo | null>(null);
  const [axVersionLoading, setAxVersionLoading] = useState(false);
  const [updateLog, setUpdateLog] = useState<
    Array<{ type: string; line: string }>
  >([]);
  const [updating, setUpdating] = useState(false);
  const [updateResult, setUpdateResult] = useState<{
    ok: boolean;
    commit: string | null;
  } | null>(null);

  useEffect(() => {
    setLocalApiUrl(getApiUrl());
  }, []);

  // Load Ax version when the updater tab is opened
  useEffect(() => {
    if (activeTab === "updater" && !axVersion && !axVersionLoading) {
      fetchAxVersion();
    }
  }, [activeTab]);

  // Poll MCP server status while the MCP tab is open
  useEffect(() => {
    if (activeTab !== "mcp") return;
    fetchMcpStatus();
    const id = setInterval(fetchMcpStatus, 4000);
    return () => clearInterval(id);
  }, [activeTab]);

  const fetchAxVersion = async () => {
    setAxVersionLoading(true);
    try {
      const res = await fetch(`${getApiUrl()}/api/axiom/version`);
      if (res.ok) {
        const data = await res.json();
        setAxVersion(data);
      }
    } catch {
      setAxVersion({ installed: false, path: "~/.axiom" });
    } finally {
      setAxVersionLoading(false);
    }
  };

  const startUpdate = async () => {
    setUpdating(true);
    setUpdateLog([]);
    setUpdateResult(null);
    try {
      const res = await fetch(`${getApiUrl()}/api/axiom/update`);
      if (!res.ok || !res.body) {
        throw new Error(`HTTP ${res.status}`);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const obj = JSON.parse(line);
            if (obj.type === "done") {
              setUpdateResult({ ok: obj.ok, commit: obj.commit });
              if (obj.ok) fetchAxVersion();
            } else {
              setUpdateLog((prev) => [
                ...prev,
                { type: obj.type, line: obj.line },
              ]);
            }
          } catch {
            setUpdateLog((prev) => [...prev, { type: "stdout", line }]);
          }
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setUpdateLog((prev) => [
        ...prev,
        { type: "error", line: `Request failed: ${msg}` },
      ]);
      setUpdateResult({ ok: false, commit: null });
    } finally {
      setUpdating(false);
    }
  };

  const handleSave = async () => {
    setStatus("checking");
    setApiUrl(apiUrl);

    // Attempt connection
    const isConnected = await checkConnection();
    setStatus(isConnected ? "connected" : "error");
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl mx-auto">
      <div className="flex items-center justify-between border-b border-slate-700 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Server className="text-primary-500" />
            System Configuration
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Manage API connections and fleet integrations
          </p>
        </div>
      </div>

      <div className="flex gap-4 border-b border-slate-700 mb-6">
        <button
          onClick={() => setActiveTab("connection")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "connection" ? "border-primary-500 text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}
        >
          Connection
        </button>
        <button
          onClick={() => setActiveTab("updater")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "updater" ? "border-primary-500 text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}
        >
          Ax Updater
        </button>
        <button
          onClick={() => setActiveTab("map")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "map" ? "border-primary-500 text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}
        >
          Map & Privacy
        </button>
        <button
          onClick={() => setActiveTab("mcp")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "mcp" ? "border-primary-500 text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}
        >
          MCP Server
        </button>
      </div>

      {activeTab === "connection" && (
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Bridge URL
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={apiUrl}
                onChange={(e) => {
                  setLocalApiUrl(e.target.value);
                  setStatus("idle");
                }}
                placeholder="http://localhost:5000"
                className="flex-1 bg-slate-900 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary-500 font-mono"
              />
              <button
                onClick={handleSave}
                className="bg-primary-600 hover:bg-primary-500 text-white px-6 py-2 rounded-lg font-medium flex items-center gap-2 transition-colors"
              >
                <Save className="w-4 h-4" /> Save & Test
              </button>
            </div>
            <p className="text-xs text-slate-500 mt-2">
              URL of the running <code className="font-mono">ax-bridge.py</code>{" "}
              process. Defaults to{" "}
              <code className="font-mono">http://localhost:5000</code>.
            </p>
          </div>

          <div className="bg-slate-900 rounded-lg p-4 flex items-center gap-4">
            <div className="text-sm font-medium text-slate-400">
              Health check:
            </div>
            {status === "idle" && (
              <span className="text-slate-500 text-sm">—</span>
            )}
            {status === "checking" && (
              <span className="text-blue-400 text-sm animate-pulse flex items-center gap-1">
                <RefreshCw className="w-3 h-3 animate-spin" /> Checking…
              </span>
            )}
            {status === "connected" && (
              <span className="text-emerald-400 text-sm flex items-center gap-1">
                <CheckCircle className="w-4 h-4" /> Bridge is reachable
              </span>
            )}
            {status === "error" && (
              <span className="text-red-400 text-sm flex items-center gap-1">
                <XCircle className="w-4 h-4" /> Bridge not reachable
              </span>
            )}
          </div>
        </div>
      )}

      {activeTab === "updater" && (
        <div className="space-y-4">
          {/* Version info card */}
          <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-primary-400" />
                Ax Framework
              </h3>
              <button
                onClick={fetchAxVersion}
                disabled={axVersionLoading}
                className="text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1 transition-colors"
              >
                <RefreshCw
                  className={`w-3 h-3 ${axVersionLoading ? "animate-spin" : ""}`}
                />
                Refresh
              </button>
            </div>

            {axVersionLoading && (
              <p className="text-slate-400 text-sm animate-pulse">
                Loading version info…
              </p>
            )}

            {!axVersionLoading && axVersion && !axVersion.installed && (
              <div className="flex items-start gap-2 text-yellow-400 text-sm">
                <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span>
                  Ax not found at{" "}
                  <code className="font-mono">{axVersion.path}</code>. Run the
                  installer to set it up.
                </span>
              </div>
            )}

            {!axVersionLoading && axVersion?.installed && (
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-slate-900 rounded p-3">
                  <p className="text-slate-400 text-xs mb-1">Branch</p>
                  <p className="text-white font-mono">
                    {axVersion.branch ?? "—"}
                  </p>
                </div>
                <div className="bg-slate-900 rounded p-3">
                  <p className="text-slate-400 text-xs mb-1">Commit</p>
                  <p className="text-white font-mono">
                    {axVersion.commit ?? "—"}
                  </p>
                </div>
                <div className="bg-slate-900 rounded p-3">
                  <p className="text-slate-400 text-xs mb-1">Last updated</p>
                  <p className="text-white text-xs">{axVersion.date ?? "—"}</p>
                </div>
                <div className="bg-slate-900 rounded p-3">
                  <p className="text-slate-400 text-xs mb-1">Modules</p>
                  <p className="text-white flex items-center gap-1">
                    <Package className="w-3 h-3 text-primary-400" />
                    {axVersion.module_count ?? 0} installed
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Update button */}
          <div className="bg-slate-800 p-6 rounded-lg border border-slate-700">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h4 className="text-white font-medium">Pull latest Ax</h4>
                <p className="text-slate-400 text-xs mt-1">
                  Runs{" "}
                  <code className="font-mono text-primary-400">
                    git pull --ff-only
                  </code>{" "}
                  on <code className="font-mono text-slate-300">~/.axiom</code>{" "}
                  and streams live output below.
                </p>
              </div>
              <button
                onClick={startUpdate}
                disabled={updating || !axVersion?.installed}
                className={`flex items-center gap-2 px-5 py-2 rounded-lg font-medium text-sm transition-colors ${
                  updating
                    ? "bg-slate-600 text-slate-400 cursor-not-allowed"
                    : "bg-primary-600 hover:bg-primary-500 text-white"
                }`}
              >
                <RefreshCw
                  className={`w-4 h-4 ${updating ? "animate-spin" : ""}`}
                />
                {updating ? "Updating…" : "Pull latest Ax"}
              </button>
            </div>

            {updateResult && (
              <div
                className={`flex items-center gap-2 text-sm mb-3 ${updateResult.ok ? "text-emerald-400" : "text-red-400"}`}
              >
                {updateResult.ok ? (
                  <>
                    <CheckCircle className="w-4 h-4" /> Update complete —
                    commit: {updateResult.commit}
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4" /> Update failed — see log
                    below
                  </>
                )}
              </div>
            )}

            {updateLog.length > 0 && (
              <div className="bg-slate-950 rounded-lg p-4">
                <div className="flex items-center gap-2 text-slate-400 text-xs mb-2">
                  <Terminal className="w-3 h-3" /> Output
                </div>
                <pre className="text-xs font-mono space-y-0.5 max-h-64 overflow-y-auto">
                  {updateLog.map((entry, i) => (
                    <div
                      key={i}
                      className={
                        entry.type === "error"
                          ? "text-red-400"
                          : entry.type === "success"
                            ? "text-emerald-400"
                            : entry.type === "info"
                              ? "text-blue-300"
                              : "text-slate-300"
                      }
                    >
                      {entry.line || " "}
                    </div>
                  ))}
                </pre>
              </div>
            )}
          </div>

          {/* Manual alternative */}
          <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50 text-sm text-slate-400">
            <p className="mb-2 font-medium text-slate-300">
              Or update manually:
            </p>
            <code className="block bg-slate-900 p-2 rounded font-mono text-emerald-400 text-xs">
              bash tools/ax-update.sh
            </code>
            <p className="mt-2 text-xs">
              Use{" "}
              <code className="font-mono text-slate-300">
                bash tools/gui-ax-install.sh --update
              </code>{" "}
              to update both the dashboard and Ax at once.
            </p>
          </div>
        </div>
      )}

      {activeTab === "map" && (
        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 space-y-6">
          <div>
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-primary-400" />
              Geo Map — IP Geolocation
            </h3>
            <p className="text-slate-400 text-sm mt-1">
              The map can place assets by geolocating their IP addresses. The
              offline provider (MaxMind GeoLite2) always stays on your machine.
            </p>
          </div>

          <div className="bg-slate-900 rounded-lg p-4 flex items-start justify-between gap-4">
            <div className="flex-1">
              <div className="text-sm font-medium text-slate-200">
                Allow online IP lookups (ip-api.com)
              </div>
              <p className="text-xs text-slate-500 mt-1 max-w-xl">
                When enabled, the Geo Map offers an{" "}
                <span className="font-mono text-slate-300">Online</span> button
                that geolocates hosts via the free ip-api.com service — no
                signup needed, but{" "}
                <span className="text-amber-400">
                  your target IP addresses are sent to a third party
                </span>
                . Disable this to hide the button entirely and keep all
                geolocation offline.
              </p>
            </div>
            <button
              role="switch"
              aria-checked={onlineGeo}
              onClick={toggleOnlineGeo}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none ${
                onlineGeo ? "bg-primary-600" : "bg-slate-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  onlineGeo ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          <p className="text-xs text-slate-500">
            {onlineGeo
              ? "Online lookups are allowed. The offline provider is still preferred when a GeoLite2 database is installed."
              : "Online lookups are disabled — only the offline GeoLite2 provider will be offered."}
          </p>
        </div>
      )}

      {activeTab === "mcp" && (
        <div className="space-y-4">
          <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 space-y-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                  <Plug className="w-5 h-5 text-primary-400" />
                  MCP Server
                </h3>
                <p className="text-slate-400 text-sm mt-1 max-w-2xl">
                  Exposes the dashboard over the Model Context Protocol so AI and
                  reporting tools (e.g. Ghostwriter via an MCP-capable agent) can
                  launch scans, read vulnerabilities and manage users/teams —
                  acting as your account. All scans it launches auto-terminate
                  their cloud fleet.
                </p>
              </div>
              {/* Status pill */}
              {mcp && (
                <span
                  className={`flex items-center gap-1 text-xs font-medium px-2.5 py-1 rounded-full whitespace-nowrap ${
                    mcp.running
                      ? "bg-emerald-500/10 text-emerald-400"
                      : "bg-slate-700 text-slate-400"
                  }`}
                >
                  {mcp.running ? (
                    <>
                      <CheckCircle className="w-3 h-3" /> Running
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3 h-3" /> Stopped
                    </>
                  )}
                </span>
              )}
            </div>

            {mcp && !mcp.available && (
              <div className="flex items-start gap-2 text-yellow-400 text-sm">
                <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span>
                  <code className="font-mono">tools/mcp-server.py</code> was not
                  found on the bridge host, so the server can't be started here.
                </span>
              </div>
            )}

            {/* Toggle + port */}
            <div className="bg-slate-900 rounded-lg p-4 flex items-center justify-between gap-4">
              <div className="flex-1">
                <div className="text-sm font-medium text-slate-200">
                  {mcp?.running
                    ? "MCP server is on"
                    : "Turn on the MCP server"}
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Starts a network (streamable-HTTP) MCP endpoint that clients
                  connect to. Requires admin.
                </p>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <label className="text-xs text-slate-500">Port</label>
                  <input
                    type="number"
                    value={mcpPort}
                    disabled={mcp?.running || mcpBusy}
                    onChange={(e) => setMcpPort(Number(e.target.value))}
                    className="w-20 bg-slate-800 border border-slate-600 rounded px-2 py-1 text-white text-sm font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
                  />
                </div>
                <button
                  role="switch"
                  aria-checked={!!mcp?.running}
                  disabled={mcpBusy || (mcp ? !mcp.available : true)}
                  onClick={toggleMcp}
                  className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none disabled:opacity-40 ${
                    mcp?.running ? "bg-primary-600" : "bg-slate-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      mcp?.running ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>

            {mcpError && (
              <div className="flex items-start gap-2 text-red-400 text-sm">
                <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span>{mcpError}</span>
              </div>
            )}

            {/* Live details when running */}
            {mcp?.running && (
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-slate-900 rounded p-3 col-span-2">
                  <p className="text-slate-400 text-xs mb-1">Client endpoint</p>
                  <div className="flex items-center gap-2">
                    <code className="text-emerald-400 font-mono text-xs break-all">
                      {mcp.endpoint ?? "—"}
                    </code>
                    {mcp.endpoint && (
                      <button
                        onClick={() =>
                          navigator.clipboard?.writeText(mcp.endpoint!)
                        }
                        title="Copy endpoint"
                        className="text-slate-400 hover:text-slate-200"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
                <div className="bg-slate-900 rounded p-3">
                  <p className="text-slate-400 text-xs mb-1">Acting as</p>
                  <p className="text-white font-mono text-xs">
                    {mcp.actingAs ?? "(unauthenticated)"}
                  </p>
                </div>
                <div className="bg-slate-900 rounded p-3">
                  <p className="text-slate-400 text-xs mb-1">PID · transport</p>
                  <p className="text-white font-mono text-xs">
                    {mcp.pid} · {mcp.transport}
                  </p>
                </div>
              </div>
            )}

            {/* Log tail */}
            {mcp?.logTail && mcp.logTail.length > 0 && (
              <div className="bg-slate-950 rounded-lg p-4">
                <div className="flex items-center gap-2 text-slate-400 text-xs mb-2">
                  <Terminal className="w-3 h-3" /> Server log
                </div>
                <pre className="text-xs font-mono space-y-0.5 max-h-48 overflow-y-auto text-slate-300">
                  {mcp.logTail.map((line, i) => (
                    <div key={i}>{line || " "}</div>
                  ))}
                </pre>
              </div>
            )}
          </div>

          {/* stdio note */}
          <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50 text-sm text-slate-400">
            <p className="mb-2 font-medium text-slate-300">
              Using Claude Desktop (stdio)?
            </p>
            <p className="text-xs mb-2">
              The toggle above runs a network server for remote clients. For a
              local stdio client, launch it directly instead:
            </p>
            <code className="block bg-slate-900 p-2 rounded font-mono text-emerald-400 text-xs">
              python3 tools/mcp-server.py
            </code>
          </div>
        </div>
      )}
    </div>
  );
};

export default Settings;
