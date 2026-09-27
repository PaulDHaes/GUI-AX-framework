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
  Sparkles,
  FolderOpen,
  Plus,
  Trash2,
  Pencil,
} from "lucide-react";
import {
  getApiUrl,
  setApiUrl,
  checkConnection,
} from "../services/axiomProvider";
import {
  getOnlineGeoEnabled,
  setOnlineGeoEnabled,
  getAiProvider,
  setAiProvider,
  AiProvider,
} from "../services/prefs";

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
    "connection" | "updater" | "map" | "mcp" | "ai" | "projects"
  >("connection");

  // ── AI provider state ────────────────────────────────────────────────────
  interface AiStatus {
    claude: boolean;
    claudeModel: string;
    ollama: boolean;
    ollamaUrl: string;
    ollamaModel: string;
  }
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  const [aiProvider, setAiProviderState] = useState<AiProvider>(getAiProvider());

  const fetchAiStatus = async () => {
    try {
      const res = await fetch(`${getApiUrl()}/api/ai/status`);
      if (res.ok) setAiStatus(await res.json());
    } catch {
      setAiStatus(null);
    }
  };

  const changeAiProvider = (p: AiProvider) => {
    setAiProvider(p);
    setAiProviderState(p);
  };

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

  // ── Projects state ───────────────────────────────────────────────────────
  interface AxProject { token: string; name: string; client: string; project_type: string; ghostwriter_id?: number | null; createdBy?: string; createdAt?: string; }
  const [projects, setProjects] = useState<AxProject[]>([]);
  const [projLoading, setProjLoading] = useState(false);
  const [projError, setProjError] = useState<string | null>(null);
  const [projForm, setProjForm] = useState({ name: "", client: "", project_type: "" });
  const [projSaving, setProjSaving] = useState(false);
  const [projSaveError, setProjSaveError] = useState<string | null>(null);
  const [editingToken, setEditingToken] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ name: "", client: "", project_type: "" });

  const PROJECT_TYPES = [
    { value: "", label: "General" },
    { value: "PCI", label: "PCI Pentest (PCI)" },
    { value: "WAPT", label: "Web Application Pentest (WAPT)" },
    { value: "CRTO", label: "Continuous Red Team (CRTO)" },
    { value: "NPT", label: "Network Pentest (NPT)" },
    { value: "SSCR", label: "Secure Code Review (SSCR)" },
    { value: "AIPT", label: "AI Pentest (AIPT)" },
    { value: "MAPT", label: "Mobile Pentest (MAPT)" },
    { value: "PTO", label: "Purple Team (PTO)" },
    { value: "RTO", label: "Red Team (RTO)" },
    { value: "MFPT", label: "Mainframe Pentest (MFPT)" },
  ];

  const fetchProjects = async () => {
    setProjLoading(true);
    setProjError(null);
    try {
      const r = await fetch(`${getApiUrl()}/api/projects/mine`, { credentials: "include" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setProjects(Array.isArray(d) ? d : Object.values(d));
    } catch (e: unknown) {
      setProjError(e instanceof Error ? e.message : String(e));
    } finally {
      setProjLoading(false);
    }
  };

  const createProject = async () => {
    if (!projForm.name.trim() || !projForm.client.trim()) return;
    setProjSaving(true);
    setProjSaveError(null);
    try {
      const r = await fetch(`${getApiUrl()}/api/projects`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(projForm),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        throw new Error(d.error || `HTTP ${r.status}`);
      }
      setProjForm({ name: "", client: "", project_type: "" });
      await fetchProjects();
    } catch (e: unknown) {
      setProjSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setProjSaving(false);
    }
  };

  const deleteProject = async (token: string) => {
    if (!confirm("Delete this project? Scan data is kept, only the project record is removed.")) return;
    try {
      await fetch(`${getApiUrl()}/api/projects/${token}`, { method: "DELETE", credentials: "include" });
      await fetchProjects();
    } catch { /* ignore */ }
  };

  const saveEdit = async (token: string) => {
    try {
      await fetch(`${getApiUrl()}/api/projects/${token}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editForm),
      });
      setEditingToken(null);
      await fetchProjects();
    } catch { /* ignore */ }
  };

  useEffect(() => {
    if (activeTab === "projects") fetchProjects();
  }, [activeTab]);

  // Fetch AI status when the AI tab is opened
  useEffect(() => {
    if (activeTab === "ai") fetchAiStatus();
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
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Server className="text-primary-500" />
            System Configuration
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Manage API connections and fleet integrations
          </p>
        </div>
      </div>

      <div className="flex gap-4 border-b border-border mb-6">
        <button
          onClick={() => setActiveTab("connection")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "connection" ? "border-primary-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          Connection
        </button>
        <button
          onClick={() => setActiveTab("updater")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "updater" ? "border-primary-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          Ax Updater
        </button>
        <button
          onClick={() => setActiveTab("map")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "map" ? "border-primary-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          Map & Privacy
        </button>
        <button
          onClick={() => setActiveTab("mcp")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "mcp" ? "border-primary-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          MCP Server
        </button>
        <button
          onClick={() => setActiveTab("ai")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "ai" ? "border-primary-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          AI Analysis
        </button>
        <button
          onClick={() => setActiveTab("projects")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === "projects" ? "border-primary-500 text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          Projects
        </button>
      </div>

      {activeTab === "connection" && (
        <div className="bg-card p-6 rounded-lg border border-border space-y-6">
          <div>
            <label className="block text-sm font-medium text-foreground mb-2">
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
                className="flex-1 bg-background border border-input rounded-lg px-4 py-2 text-foreground focus:outline-none focus:border-primary-500 font-mono"
              />
              <button
                onClick={handleSave}
                className="bg-primary-600 hover:bg-primary-500 text-foreground px-6 py-2 rounded-lg font-medium flex items-center gap-2 transition-colors"
              >
                <Save className="w-4 h-4" /> Save & Test
              </button>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              URL of the running <code className="font-mono">ax-bridge.py</code>{" "}
              process. Defaults to{" "}
              <code className="font-mono">http://localhost:5000</code>.
            </p>
          </div>

          <div className="bg-background rounded-lg p-4 flex items-center gap-4 border border-border">
            <div className="text-sm font-medium text-muted-foreground">
              Health check:
            </div>
            {status === "idle" && (
              <span className="text-muted-foreground text-sm">—</span>
            )}
            {status === "checking" && (
              <span className="text-blue-500 dark:text-blue-400 text-sm animate-pulse flex items-center gap-1">
                <RefreshCw className="w-3 h-3 animate-spin" /> Checking…
              </span>
            )}
            {status === "connected" && (
              <span className="text-green-600 dark:text-green-400 text-sm flex items-center gap-1">
                <CheckCircle className="w-4 h-4" /> Bridge is reachable
              </span>
            )}
            {status === "error" && (
              <span className="text-red-600 dark:text-red-400 text-sm flex items-center gap-1">
                <XCircle className="w-4 h-4" /> Bridge not reachable
              </span>
            )}
          </div>
        </div>
      )}

      {activeTab === "updater" && (
        <div className="space-y-4">
          {/* Version info card */}
          <div className="bg-card p-6 rounded-lg border border-border">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-primary-400" />
                Ax Framework
              </h3>
              <button
                onClick={fetchAxVersion}
                disabled={axVersionLoading}
                className="text-muted-foreground hover:text-foreground text-xs flex items-center gap-1 transition-colors"
              >
                <RefreshCw
                  className={`w-3 h-3 ${axVersionLoading ? "animate-spin" : ""}`}
                />
                Refresh
              </button>
            </div>

            {axVersionLoading && (
              <p className="text-muted-foreground text-sm animate-pulse">
                Loading version info…
              </p>
            )}

            {!axVersionLoading && axVersion && !axVersion.installed && (
              <div className="flex items-start gap-2 text-yellow-600 dark:text-yellow-400 text-sm">
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
                <div className="bg-muted/50 rounded p-3">
                  <p className="text-muted-foreground text-xs mb-1">Branch</p>
                  <p className="text-foreground font-mono">
                    {axVersion.branch ?? "—"}
                  </p>
                </div>
                <div className="bg-muted/50 rounded p-3">
                  <p className="text-muted-foreground text-xs mb-1">Commit</p>
                  <p className="text-foreground font-mono">
                    {axVersion.commit ?? "—"}
                  </p>
                </div>
                <div className="bg-muted/50 rounded p-3">
                  <p className="text-muted-foreground text-xs mb-1">Last updated</p>
                  <p className="text-foreground text-xs">{axVersion.date ?? "—"}</p>
                </div>
                <div className="bg-muted/50 rounded p-3">
                  <p className="text-muted-foreground text-xs mb-1">Modules</p>
                  <p className="text-foreground flex items-center gap-1">
                    <Package className="w-3 h-3 text-primary-400" />
                    {axVersion.module_count ?? 0} installed
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Update button */}
          <div className="bg-card p-6 rounded-lg border border-border">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h4 className="text-foreground font-medium">Pull latest Ax</h4>
                <p className="text-muted-foreground text-xs mt-1">
                  Runs{" "}
                  <code className="font-mono text-primary-400">
                    git pull --ff-only
                  </code>{" "}
                  on <code className="font-mono">~/.axiom</code>{" "}
                  and streams live output below.
                </p>
              </div>
              <button
                onClick={startUpdate}
                disabled={updating || !axVersion?.installed}
                className={`flex items-center gap-2 px-5 py-2 rounded-lg font-medium text-sm transition-colors ${
                  updating
                    ? "bg-muted text-muted-foreground cursor-not-allowed"
                    : "bg-primary-600 hover:bg-primary-500 text-foreground"
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
                className={`flex items-center gap-2 text-sm mb-3 ${updateResult.ok ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}
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
              <div className="bg-background rounded-lg p-4 border border-border">
                <div className="flex items-center gap-2 text-muted-foreground text-xs mb-2">
                  <Terminal className="w-3 h-3" /> Output
                </div>
                <pre className="text-xs font-mono space-y-0.5 max-h-64 overflow-y-auto">
                  {updateLog.map((entry, i) => (
                    <div
                      key={i}
                      className={
                        entry.type === "error"
                          ? "text-red-600 dark:text-red-400"
                          : entry.type === "success"
                            ? "text-green-600 dark:text-green-400"
                            : entry.type === "info"
                              ? "text-blue-600 dark:text-blue-300"
                              : "text-foreground/80"
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
          <div className="bg-card/50 p-4 rounded-lg border border-border text-sm text-muted-foreground">
            <p className="mb-2 font-medium text-foreground">
              Or update manually:
            </p>
            <code className="block bg-background p-2 rounded font-mono text-green-600 dark:text-green-400 text-xs border border-border">
              bash tools/ax-update.sh
            </code>
            <p className="mt-2 text-xs">
              Use{" "}
              <code className="font-mono text-foreground">
                bash tools/gui-ax-install.sh --update
              </code>{" "}
              to update both the dashboard and Ax at once.
            </p>
          </div>
        </div>
      )}

      {activeTab === "map" && (
        <div className="bg-card p-6 rounded-lg border border-border space-y-6">
          <div>
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Globe className="w-5 h-5 text-primary-400" />
              Geo Map — IP Geolocation
            </h3>
            <p className="text-muted-foreground text-sm mt-1">
              The map can place assets by geolocating their IP addresses. The
              offline provider (MaxMind GeoLite2) always stays on your machine.
            </p>
          </div>

          <div className="bg-background rounded-lg p-4 flex items-start justify-between gap-4 border border-border">
            <div className="flex-1">
              <div className="text-sm font-medium text-foreground">
                Allow online IP lookups (ip-api.com)
              </div>
              <p className="text-xs text-muted-foreground mt-1 max-w-xl">
                When enabled, the Geo Map offers an{" "}
                <span className="font-mono text-foreground">Online</span> button
                that geolocates hosts via the free ip-api.com service — no
                signup needed, but{" "}
                <span className="text-amber-600 dark:text-amber-400">
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
                onlineGeo ? "bg-primary-600" : "bg-muted"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  onlineGeo ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          <p className="text-xs text-muted-foreground">
            {onlineGeo
              ? "Online lookups are allowed. The offline provider is still preferred when a GeoLite2 database is installed."
              : "Online lookups are disabled — only the offline GeoLite2 provider will be offered."}
          </p>
        </div>
      )}

      {activeTab === "mcp" && (
        <div className="space-y-4">
          <div className="bg-card p-6 rounded-lg border border-border space-y-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  <Plug className="w-5 h-5 text-primary-400" />
                  MCP Server
                </h3>
                <p className="text-muted-foreground text-sm mt-1 max-w-2xl">
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
                      ? "bg-green-500/10 text-green-600 dark:text-green-400"
                      : "bg-muted text-muted-foreground"
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
              <div className="flex items-start gap-2 text-yellow-600 dark:text-yellow-400 text-sm">
                <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span>
                  <code className="font-mono">tools/mcp-server.py</code> was not
                  found on the bridge host, so the server can't be started here.
                </span>
              </div>
            )}

            {/* Toggle + port */}
            <div className="bg-background rounded-lg p-4 flex items-center justify-between gap-4 border border-border">
              <div className="flex-1">
                <div className="text-sm font-medium text-foreground">
                  {mcp?.running
                    ? "MCP server is on"
                    : "Turn on the MCP server"}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Starts a network (streamable-HTTP) MCP endpoint that clients
                  connect to. Requires admin.
                </p>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <label className="text-xs text-muted-foreground">Port</label>
                  <input
                    type="number"
                    value={mcpPort}
                    disabled={mcp?.running || mcpBusy}
                    onChange={(e) => setMcpPort(Number(e.target.value))}
                    className="w-20 bg-card border border-input rounded px-2 py-1 text-foreground text-sm font-mono focus:outline-none focus:border-primary-500 disabled:opacity-50"
                  />
                </div>
                <button
                  role="switch"
                  aria-checked={!!mcp?.running}
                  disabled={mcpBusy || (mcp ? !mcp.available : true)}
                  onClick={toggleMcp}
                  className={`relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none disabled:opacity-40 ${
                    mcp?.running ? "bg-primary-600" : "bg-muted"
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
              <div className="flex items-start gap-2 text-red-600 dark:text-red-400 text-sm">
                <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <span>{mcpError}</span>
              </div>
            )}

            {/* Live details when running */}
            {mcp?.running && (
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-background rounded p-3 col-span-2 border border-border">
                  <p className="text-muted-foreground text-xs mb-1">Client endpoint</p>
                  <div className="flex items-center gap-2">
                    <code className="text-green-600 dark:text-green-400 font-mono text-xs break-all">
                      {mcp.endpoint ?? "—"}
                    </code>
                    {mcp.endpoint && (
                      <button
                        onClick={() =>
                          navigator.clipboard?.writeText(mcp.endpoint!)
                        }
                        title="Copy endpoint"
                        className="text-muted-foreground hover:text-foreground"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
                <div className="bg-background rounded p-3 border border-border">
                  <p className="text-muted-foreground text-xs mb-1">Acting as</p>
                  <p className="text-foreground font-mono text-xs">
                    {mcp.actingAs ?? "(unauthenticated)"}
                  </p>
                </div>
                <div className="bg-background rounded p-3 border border-border">
                  <p className="text-muted-foreground text-xs mb-1">PID · transport</p>
                  <p className="text-foreground font-mono text-xs">
                    {mcp.pid} · {mcp.transport}
                  </p>
                </div>
              </div>
            )}

            {/* Log tail */}
            {mcp?.logTail && mcp.logTail.length > 0 && (
              <div className="bg-background rounded-lg p-4 border border-border">
                <div className="flex items-center gap-2 text-muted-foreground text-xs mb-2">
                  <Terminal className="w-3 h-3" /> Server log
                </div>
                <pre className="text-xs font-mono space-y-0.5 max-h-48 overflow-y-auto text-foreground/80">
                  {mcp.logTail.map((line, i) => (
                    <div key={i}>{line || " "}</div>
                  ))}
                </pre>
              </div>
            )}
          </div>

          {/* stdio note */}
          <div className="bg-card/50 p-4 rounded-lg border border-border text-sm text-muted-foreground">
            <p className="mb-2 font-medium text-foreground">
              Using Claude Desktop (stdio)?
            </p>
            <p className="text-xs mb-2">
              The toggle above runs a network server for remote clients. For a
              local stdio client, launch it directly instead:
            </p>
            <code className="block bg-background p-2 rounded font-mono text-green-600 dark:text-green-400 text-xs border border-border">
              python3 tools/mcp-server.py
            </code>
          </div>
        </div>
      )}

      {/* ── AI Analysis tab ──────────────────────────────────────────────── */}
      {activeTab === "ai" && (
        <div className="space-y-5">
          {/* Header */}
          <div className="flex items-center gap-3 pb-1">
            <Sparkles className="w-5 h-5 text-primary-400" />
            <div>
              <h3 className="text-foreground font-semibold">AI Analysis</h3>
              <p className="text-muted-foreground text-xs mt-0.5">
                Power risk analysis and the security assistant with an LLM.
                Keys are set in <code className="font-mono">.env</code> —
                no key needed to use local analysis.
              </p>
            </div>
          </div>

          {/* Provider status */}
          <div className="bg-card rounded-lg border border-border p-4 space-y-3">
            <p className="text-foreground text-sm font-medium mb-3">
              Provider status
            </p>
            {/* Ollama (local) */}
            <div className="flex items-center justify-between py-2 border-b border-border">
              <div>
                <span className="text-sm font-medium text-purple-600 dark:text-purple-400">
                  Ollama (local)
                </span>
                <span className="text-muted-foreground text-xs ml-2 font-mono">
                  {aiStatus?.ollamaModel ?? "llama3.2"}
                </span>
                {aiStatus === null && (
                  <span className="text-muted-foreground/60 text-xs ml-2">(checking…)</span>
                )}
                {aiStatus && !aiStatus.ollama && (
                  <span className="text-muted-foreground text-xs ml-2 font-mono">
                    — add ollama service to docker-compose.yml
                  </span>
                )}
              </div>
              {aiStatus?.ollama ? (
                <span className="flex items-center gap-1 text-green-600 dark:text-green-400 text-xs font-medium">
                  <CheckCircle className="w-3.5 h-3.5" /> Running
                </span>
              ) : (
                <span className="flex items-center gap-1 text-muted-foreground text-xs">
                  <XCircle className="w-3.5 h-3.5" /> Not running
                </span>
              )}
            </div>

            {/* Claude (Anthropic API) */}
            <div className="flex items-center justify-between py-2 border-b border-border">
              <div>
                <span className="text-sm font-medium text-orange-600 dark:text-orange-400">
                  Claude (Anthropic)
                </span>
                <span className="text-muted-foreground text-xs ml-2 font-mono">
                  {aiStatus?.claudeModel ?? "claude-haiku-4-5-20251001"}
                </span>
                {aiStatus === null && (
                  <span className="text-muted-foreground/60 text-xs ml-2">(checking…)</span>
                )}
                {aiStatus && !aiStatus.claude && (
                  <span className="text-muted-foreground text-xs ml-2 font-mono">
                    — set ANTHROPIC_API_KEY in .env
                  </span>
                )}
              </div>
              {aiStatus?.claude ? (
                <span className="flex items-center gap-1 text-green-600 dark:text-green-400 text-xs font-medium">
                  <CheckCircle className="w-3.5 h-3.5" /> Configured
                </span>
              ) : (
                <span className="flex items-center gap-1 text-muted-foreground text-xs">
                  <XCircle className="w-3.5 h-3.5" /> Not set
                </span>
              )}
            </div>

            {/* Local fallback always available */}
            <div className="flex items-center justify-between py-2">
              <div>
                <span className="text-sm font-medium text-foreground">
                  Local (deterministic)
                </span>
                <span className="text-muted-foreground text-xs ml-2">
                  — no API key required
                </span>
              </div>
              <span className="flex items-center gap-1 text-green-600 dark:text-green-400 text-xs font-medium">
                <CheckCircle className="w-3.5 h-3.5" /> Always available
              </span>
            </div>
          </div>

          {/* Provider preference */}
          <div className="bg-card rounded-lg border border-border p-4">
            <p className="text-foreground text-sm font-medium mb-3">
              Preferred provider
            </p>
            <div className="space-y-2">
              {(
                [
                  {
                    value: "auto",
                    label: "Auto",
                    desc: "Prefers Ollama (local) → Claude → local fallback",
                  },
                  {
                    value: "ollama",
                    label: "Ollama (local)",
                    desc: "Always use local Ollama — data never leaves your machine",
                  },
                  {
                    value: "claude",
                    label: "Claude",
                    desc: "Always use Claude API (requires ANTHROPIC_API_KEY)",
                  },
                  {
                    value: "local",
                    label: "Local only",
                    desc: "Deterministic risk scorer — no AI calls made",
                  },
                ] as { value: AiProvider; label: string; desc: string }[]
              ).map(({ value, label, desc }) => (
                <label
                  key={value}
                  className="flex items-start gap-3 p-3 rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
                >
                  <input
                    type="radio"
                    name="aiProvider"
                    value={value}
                    checked={aiProvider === value}
                    onChange={() => changeAiProvider(value)}
                    className="mt-0.5 accent-primary-500"
                  />
                  <div>
                    <span className="text-sm text-foreground font-medium">
                      {label}
                    </span>
                    <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Info note */}
          <div className="bg-card/50 p-4 rounded-lg border border-border text-sm text-muted-foreground">
            <p className="mb-1 font-medium text-foreground">
              How to add an API key
            </p>
            <p className="text-xs mb-2">
              Edit your <code className="font-mono text-foreground">.env</code>{" "}
              file (or <code className="font-mono text-foreground">docker-compose.yml</code>{" "}
              env section) and restart the container:
            </p>
            <p className="text-xs mb-1 font-medium text-foreground">Ollama / LiteLLM (recommended — data stays local):</p>
            <code className="block bg-background p-2 rounded font-mono text-purple-600 dark:text-purple-400 text-xs whitespace-pre border border-border mb-3">
              {`# Mac Ollama (from inside Docker):\nOLLAMA_URL=http://host.docker.internal:11434\n\n# LiteLLM proxy on another host:\nOLLAMA_URL=http://192.168.x.x:4000\n\n# Override model:\nOLLAMA_MODEL=llama3.2`}
            </code>
            <p className="text-xs mb-1 font-medium text-foreground">Claude API (optional — sends data to Anthropic):</p>
            <code className="block bg-background p-2 rounded font-mono text-green-600 dark:text-green-400 text-xs whitespace-pre border border-border">
              {`ANTHROPIC_API_KEY=sk-ant-…`}
            </code>
            <p className="text-xs mt-2">
              Set these in docker-compose.yml env section and restart. Ollama/LiteLLM keeps all pentest data off external servers.
            </p>
          </div>
        </div>
      )}

      {activeTab === "projects" && (
        <div className="space-y-6">
          {/* Info banner */}
          <div className="bg-card border border-border rounded-lg p-4 text-sm text-muted-foreground">
            <p className="flex items-start gap-2">
              <FolderOpen className="w-4 h-4 mt-0.5 shrink-0 text-primary-400" />
              <span>
                Projects scope the dashboard, vulnerability list, and triage to a specific engagement.
                Projects synced from <strong className="text-foreground">Ghostwriter</strong> are managed there;
                standalone projects (created below) are stored in the bridge only and work without Ghostwriter.
              </span>
            </p>
          </div>

          {/* Create new project */}
          <div className="bg-card border border-border rounded-lg p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <Plus className="w-4 h-4 text-primary-400" /> Create Project
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Client / Company *</label>
                <input
                  type="text"
                  value={projForm.client}
                  onChange={(e) => setProjForm((f) => ({ ...f, client: e.target.value }))}
                  placeholder="Acme Corp"
                  className="w-full bg-background border border-border rounded px-3 py-1.5 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary-500"
                />
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Project Name *</label>
                <input
                  type="text"
                  value={projForm.name}
                  onChange={(e) => setProjForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="External Pentest Q3"
                  className="w-full bg-background border border-border rounded px-3 py-1.5 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary-500"
                />
              </div>
              <div>
                <label className="block text-xs text-muted-foreground mb-1">Type</label>
                <select
                  value={projForm.project_type}
                  onChange={(e) => setProjForm((f) => ({ ...f, project_type: e.target.value }))}
                  className="w-full bg-background border border-border rounded px-3 py-1.5 text-sm text-foreground focus:outline-none focus:border-primary-500"
                >
                  {PROJECT_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
            </div>
            {projSaveError && (
              <p className="text-xs text-red-400">{projSaveError}</p>
            )}
            <button
              onClick={createProject}
              disabled={projSaving || !projForm.name.trim() || !projForm.client.trim()}
              className="px-4 py-1.5 bg-primary-500 hover:bg-primary-600 disabled:opacity-50 text-white text-sm font-medium rounded transition-colors"
            >
              {projSaving ? "Creating…" : "Create Project"}
            </button>
          </div>

          {/* Project list */}
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-5 py-3 border-b border-border flex items-center justify-between">
              <h3 className="font-semibold text-foreground text-sm">Your Projects</h3>
              <button onClick={fetchProjects} className="text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                <RefreshCw className="w-3 h-3" /> Refresh
              </button>
            </div>

            {projLoading ? (
              <div className="p-8 text-center text-muted-foreground text-sm">
                <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-2" /> Loading projects…
              </div>
            ) : projError ? (
              <div className="p-5 text-sm text-red-400">{projError}</div>
            ) : projects.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground text-sm font-mono">
                No projects yet — create one above or launch a scan from Ghostwriter.
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-border text-xs text-muted-foreground font-mono">
                  <tr>
                    <th className="px-5 py-2.5 text-left">Client</th>
                    <th className="px-5 py-2.5 text-left">Name</th>
                    <th className="px-5 py-2.5 text-left">Type</th>
                    <th className="px-5 py-2.5 text-left">Source</th>
                    <th className="px-5 py-2.5 text-left">Token</th>
                    <th className="px-5 py-2.5"></th>
                  </tr>
                </thead>
                <tbody>
                  {projects.map((p) => (
                    <tr key={p.token} className="border-b border-border/40 hover:bg-secondary/10 transition-colors">
                      {editingToken === p.token ? (
                        <>
                          <td className="px-5 py-2">
                            <input
                              value={editForm.client}
                              onChange={(e) => setEditForm((f) => ({ ...f, client: e.target.value }))}
                              className="w-full bg-background border border-border rounded px-2 py-1 text-xs focus:outline-none focus:border-primary-500"
                            />
                          </td>
                          <td className="px-5 py-2">
                            <input
                              value={editForm.name}
                              onChange={(e) => setEditForm((f) => ({ ...f, name: e.target.value }))}
                              className="w-full bg-background border border-border rounded px-2 py-1 text-xs focus:outline-none focus:border-primary-500"
                            />
                          </td>
                          <td className="px-5 py-2">
                            <select
                              value={editForm.project_type}
                              onChange={(e) => setEditForm((f) => ({ ...f, project_type: e.target.value }))}
                              className="bg-background border border-border rounded px-2 py-1 text-xs focus:outline-none"
                            >
                              {PROJECT_TYPES.map((t) => (
                                <option key={t.value} value={t.value}>{t.value || "General"}</option>
                              ))}
                            </select>
                          </td>
                          <td colSpan={2} />
                          <td className="px-5 py-2 text-right">
                            <button onClick={() => saveEdit(p.token)} className="text-xs text-primary-400 hover:text-primary-300 mr-3">Save</button>
                            <button onClick={() => setEditingToken(null)} className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
                          </td>
                        </>
                      ) : (
                        <>
                          <td className="px-5 py-3 font-medium">{p.client}</td>
                          <td className="px-5 py-3">{p.name}</td>
                          <td className="px-5 py-3 text-muted-foreground font-mono text-xs">{p.project_type || "—"}</td>
                          <td className="px-5 py-3">
                            {p.ghostwriter_id ? (
                              <span className="text-xs bg-blue-500/15 text-blue-400 px-1.5 py-0.5 rounded font-mono">Ghostwriter</span>
                            ) : (
                              <span className="text-xs bg-secondary text-muted-foreground px-1.5 py-0.5 rounded font-mono">Standalone</span>
                            )}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-muted-foreground max-w-[160px] truncate" title={p.token}>{p.token}</td>
                          <td className="px-5 py-3 text-right whitespace-nowrap">
                            {!p.ghostwriter_id && (
                              <button
                                onClick={() => { setEditingToken(p.token); setEditForm({ name: p.name, client: p.client, project_type: p.project_type }); }}
                                className="text-muted-foreground hover:text-foreground transition-colors mr-3"
                                title="Edit"
                              >
                                <Pencil className="w-3.5 h-3.5" />
                              </button>
                            )}
                            <button
                              onClick={() => deleteProject(p.token)}
                              className="text-muted-foreground hover:text-red-400 transition-colors"
                              title="Delete"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <p className="text-xs text-muted-foreground">
            Ghostwriter projects are created automatically when a scan is launched from a Ghostwriter project dashboard.
            The project token is used to scope scan results — all scans named <code className="font-mono">gw-&lt;client&gt;-*</code> appear under that project.
          </p>
        </div>
      )}
    </div>
  );
};

export default Settings;
