import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useNavigate,
  useLocation,
  useSearchParams,
} from "react-router-dom";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import {
  Globe,
  ShieldAlert,
  Server,
  Activity,
  Bell,
  ChevronRight,
  ChevronDown,
  LayoutDashboard,
  Settings as SettingsIcon,
  Target as TargetIcon,
  BookOpen,
  X,
  Download,
  Copy,
  Filter,
} from "lucide-react";
import ScanLauncher from "./components/ScanLauncher";
import ActiveScans from "./components/ActiveScans";
import ScanOutput from "./components/ScanOutput";
import FleetControl from "./components/FleetControl";
import TopologyGraph from "./components/TopologyGraph";
import Settings from "./components/Settings";
import GeoMap from "./components/GeoMap";
import BinocularsSkullLogo from "./components/ui/BinocularsSkullLogo";
// Types
import type { Target, FleetInstance } from "./types";
// Severity enum (if not imported from types)
import { Severity } from "./types";

// ── Notification System ─────────────────────────────────────
interface AppNotification {
  id: string;
  type: string;
  title: string;
  message: string;
  time: Date;
  read: boolean;
}

// --- Local StatCard component for dashboard stats ---
function StatCard({
  title,
  value,
  icon: Icon,
  accentClass = "",
  iconBg = "bg-primary-500/10",
  iconColor = "text-primary-400",
  trend = undefined,
  onClick = undefined,
}: any) {
  return (
    <div
      onClick={onClick}
      className={`rounded-lg p-4 flex items-center gap-3 bg-dark-800 border border-dark-700 border-l-2 card-hover ${onClick ? "cursor-pointer" : "cursor-default"} ${accentClass}`}
    >
      <div className="flex-shrink-0">
        <div
          className={`h-8 w-8 rounded flex items-center justify-center ${iconBg}`}
        >
          {Icon && <Icon className={`w-4 h-4 ${iconColor}`} />}
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-white-400 text-xs mb-0.5 font-mono">{title}</div>
        <div className="text-xl font-bold text-white tabular-nums">{value}</div>
        {trend && (
          <div className="text-xs text-success-400 mt-0.5 font-mono">
            {trend}
          </div>
        )}
      </div>
    </div>
  );
}

// --- API DATA FETCHERS ---
// Fetch targets from axiom-bridge API
async function fetchTargets() {
  try {
    const response = await fetch("http://localhost:5000/api/targets");
    if (!response.ok) {
      console.warn("Failed to fetch targets:", response.statusText);
      return [];
    }
    const data = await response.json();
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error("Error fetching targets:", error);
    return [];
  }
}

// Fetch fleet from axiom-bridge API (calls axiom-ls)
async function fetchFleet(forceRefresh = false, filter = "managed") {
  try {
    const params = new URLSearchParams();
    params.set("filter", filter);
    if (forceRefresh) params.set("refresh", "true");
    const url = `http://localhost:5000/api/fleet?${params.toString()}`;
    const response = await fetch(url);
    if (!response.ok) {
      console.warn("Failed to fetch fleet:", response.statusText);
      return [];
    }
    const data = await response.json();
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error("Error fetching fleet:", error);
    return [];
  }
}
// Helper: Get top discovered assets
function getTopAssets(targets) {
  const assetCounts = {};
  targets.forEach((t) => {
    if (t.domain) {
      assetCounts[t.domain] = (assetCounts[t.domain] || 0) + 1;
    }
  });
  return Object.entries(assetCounts)
    .map(function (entry) {
      return { name: entry[0], count: Number(entry[1]) };
    })
    .sort(function (a, b) {
      return b.count - a.count;
    })
    .slice(0, 10);
}

// Helper: Get most common found ports
function getCommonPorts(targets) {
  const portCounts: Record<string, number> = {};
  targets.forEach((t) => {
    if (!Array.isArray(t.subdomains)) return;
    t.subdomains.forEach((sub) => {
      if (!Array.isArray(sub.ports)) return;
      sub.ports.forEach((p) => {
        const key = String(p.port);
        portCounts[key] = (portCounts[key] || 0) + 1;
      });
    });
  });
  return Object.entries(portCounts)
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
}

// Helper: Categorize scan type and return appropriate metrics
function getScanMetrics(target) {
  const scanId = target.id?.toLowerCase() || "";
  const programName = target.programName?.toLowerCase() || "";
  const scanIdentifier = `${scanId} ${programName}`;

  // Subdomain/domain enumeration scans
  if (
    scanIdentifier.includes("amass") ||
    scanIdentifier.includes("subfinder") ||
    scanIdentifier.includes("assetfinder") ||
    scanIdentifier.includes("dnsx") ||
    scanIdentifier.includes("dnsgen") ||
    scanIdentifier.includes("shuffledns") ||
    scanIdentifier.includes("puredns") ||
    scanIdentifier.includes("crobat") ||
    scanIdentifier.includes("ctfr") ||
    scanIdentifier.includes("findomain") ||
    scanIdentifier.includes("github-subdomains") ||
    scanIdentifier.includes("massdns") ||
    scanIdentifier.includes("dnsrecon") ||
    scanIdentifier.includes("hakrevdns")
  ) {
    return { count: target.subdomains?.length || 0, label: "subdomains" };
  }

  // Port scanning
  if (
    scanIdentifier.includes("nmap") ||
    scanIdentifier.includes("masscan") ||
    scanIdentifier.includes("naabu") ||
    scanIdentifier.includes("rustscan") ||
    scanIdentifier.includes("unimap")
  ) {
    return { count: target.totalPorts || 0, label: "ports" };
  }

  // Web/HTTP probing & screenshots
  if (
    scanIdentifier.includes("httpx") ||
    scanIdentifier.includes("httprobe") ||
    scanIdentifier.includes("gowitness") ||
    scanIdentifier.includes("aquatone") ||
    scanIdentifier.includes("webscreenshot")
  ) {
    return { count: target.subdomains?.length || 0, label: "websites" };
  }

  // Vulnerability scanning
  if (scanIdentifier.includes("nuclei") || scanIdentifier.includes("jaeles")) {
    return { count: target.vulnerabilities?.length || 0, label: "vulns" };
  }

  // URL/endpoint discovery
  if (
    scanIdentifier.includes("gau") ||
    scanIdentifier.includes("waybackurls") ||
    scanIdentifier.includes("gospider") ||
    scanIdentifier.includes("katana") ||
    scanIdentifier.includes("hakrawler") ||
    scanIdentifier.includes("waymore") ||
    scanIdentifier.includes("paramspider") ||
    scanIdentifier.includes("github-endpoints") ||
    scanIdentifier.includes("linkfinder") ||
    scanIdentifier.includes("xnlinkfinder")
  ) {
    return { count: target.subdomains?.length || 0, label: "urls" };
  }

  // Directory/file fuzzing
  if (
    scanIdentifier.includes("ffuf") ||
    scanIdentifier.includes("feroxbuster") ||
    scanIdentifier.includes("gobuster") ||
    scanIdentifier.includes("dirdar") ||
    scanIdentifier.includes("meg")
  ) {
    return { count: target.subdomains?.length || 0, label: "paths" };
  }

  // Technology/service detection
  if (
    scanIdentifier.includes("wappalyzer") ||
    scanIdentifier.includes("wafw00f") ||
    scanIdentifier.includes("tlsx") ||
    scanIdentifier.includes("testssl")
  ) {
    return { count: target.subdomains?.length || 0, label: "services" };
  }

  // Whois and other information gathering
  if (
    scanIdentifier.includes("whois") ||
    scanIdentifier.includes("asm") ||
    scanIdentifier.includes("scrying")
  ) {
    return { count: target.subdomains?.length || 0, label: "records" };
  }

  // Default: show raw result count as lines for any unrecognised module
  return { count: target.subdomains?.length || 0, label: "lines" };
}

// Pie chart colors
const pieColors = [
  "#10b981", // emerald
  "#3b82f6", // blue
  "#f59e42", // orange
  "#ef4444", // red
  "#a78bfa", // purple
  "#fbbf24", // yellow
  "#6366f1", // indigo
  "#14b8a6", // teal
];

// Helper: Aggregate dashboard metrics
function getDashboardMetrics(targets, fleet) {
  let totalPorts = 0;
  let totalVulns = 0;
  let highCriticalVulns = 0;
  let activeScans = 0;
  let totalTargets = targets.length;
  let totalSubdomains = 0;
  let fleetUtilization =
    fleet.length > 0
      ? fleet.filter((f) => f.status === "running" || f.status === "idle")
          .length / fleet.length
      : 0;
  let fleetRegions = {};

  targets.forEach((t) => {
    totalPorts += Array.isArray(t.subdomains)
      ? t.subdomains.reduce(
          (acc, s) => acc + (Array.isArray(s.ports) ? s.ports.length : 0),
          0,
        )
      : 0;
    totalVulns += Array.isArray(t.vulnerabilities)
      ? t.vulnerabilities.length
      : 0;
    highCriticalVulns += Array.isArray(t.vulnerabilities)
      ? t.vulnerabilities.filter(
          (v) => v.severity === "HIGH" || v.severity === "CRITICAL",
        ).length
      : 0;
    totalSubdomains += Array.isArray(t.subdomains) ? t.subdomains.length : 0;
    if (t.status === "RUNNING") activeScans++;
  });
  fleet.forEach((f) => {
    const region = f.region || "Unknown";
    fleetRegions[region] = (fleetRegions[region] || 0) + 1;
  });
  return {
    totalPorts,
    totalVulns,
    highCriticalVulns,
    activeScans,
    totalTargets,
    totalSubdomains,
    fleetUtilization,
    fleetRegions,
    fleetTotal: fleet.length,
    fleetActive: fleet.filter(
      (f) => f.status === "running" || f.status === "idle",
    ).length,
  };
}

const TargetsList = ({
  targets,
  onSelectTarget,
  onRefresh,
  loading = false,
  lastUpdated = null,
}: {
  targets: Target[];
  onSelectTarget: (t: Target) => void;
  onRefresh?: () => void;
  loading?: boolean;
  lastUpdated?: Date | null;
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const navigate = useNavigate();
  const [reimporting, setReimporting] = useState(false);
  const [debugStore, setDebugStore] = useState<any>(null);
  const [debugOpen, setDebugOpen] = useState(false);

  const handleReimport = async () => {
    setReimporting(true);
    try {
      await fetch("http://localhost:5000/api/imports/reimport", {
        method: "POST",
      });
      onRefresh?.();
    } catch {
      // bridge offline
    } finally {
      setReimporting(false);
    }
  };

  const handleDebugStore = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/debug/store");
      const data = await res.json();
      setDebugStore(data);
      setDebugOpen(true);
    } catch (e) {
      setDebugStore({ error: "Could not reach bridge at localhost:5000" });
      setDebugOpen(true);
    }
  };

  // Format "X ago" label
  const updatedLabel = (() => {
    if (!lastUpdated) return null;
    const secs = Math.floor((Date.now() - lastUpdated.getTime()) / 1000);
    if (secs < 60) return "just now";
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    return `${Math.floor(secs / 3600)}h ago`;
  })();

  // Filter targets based on search query, then sort newest first
  const filteredTargets = targets
    .filter((target) => {
      if (!searchQuery.trim()) return true;
      const query = searchQuery.toLowerCase();
      return (
        target.domain?.toLowerCase().includes(query) ||
        target.programName?.toLowerCase().includes(query) ||
        target.id?.toLowerCase().includes(query)
      );
    })
    .sort(
      (a, b) =>
        new Date(b.lastScanDate || 0).getTime() -
        new Date(a.lastScanDate || 0).getTime(),
    );

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Debug Store Modal */}
      {debugOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg w-full max-w-3xl max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between px-5 py-3 border-b border-dark-700">
              <span className="text-sm font-bold text-white font-mono">
                🔍 Bridge Store Debug
              </span>
              <button
                onClick={() => setDebugOpen(false)}
                className="text-white-400 hover:text-white text-lg"
              >
                ✕
              </button>
            </div>
            <div className="overflow-auto flex-1 p-4">
              {debugStore?.error ? (
                <p className="text-red-400 font-mono text-sm">
                  {debugStore.error}
                </p>
              ) : (
                <>
                  <p className="text-xs text-white-400 font-mono mb-3">
                    Store:{" "}
                    <span className="text-cyan-300">
                      {debugStore?.store_path}
                    </span>
                    &nbsp;·&nbsp;{debugStore?.target_count} target(s)
                  </p>
                  {(debugStore?.targets ?? []).map((t: any) => (
                    <div
                      key={t.id}
                      className="mb-4 bg-dark-900 rounded-lg border border-dark-700 p-3"
                    >
                      <p className="text-xs font-mono text-white mb-1">
                        <span className="text-yellow-300">id:</span> {t.id}
                      </p>
                      <p className="text-xs font-mono text-white mb-1">
                        <span className="text-yellow-300">domain:</span>{" "}
                        {t.domain}
                      </p>
                      <p className="text-xs font-mono text-white mb-1">
                        <span className="text-yellow-300">sources:</span>{" "}
                        {JSON.stringify(t.sources)}
                      </p>
                      <p className="text-xs font-mono text-white mb-1">
                        <span className="text-yellow-300">subdomains:</span>{" "}
                        {JSON.stringify(t.subdomains)}
                      </p>
                    </div>
                  ))}
                  {(debugStore?.targets ?? []).length === 0 && (
                    <p className="text-red-400 font-mono text-sm">
                      ⚠ Store is empty — no targets. Try ↩ Re-import first.
                    </p>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-3">
          <span className="text-sm font-semibold text-white-300 font-mono">
            Targets
          </span>
          <span className="text-xs text-white-600 font-mono">
            {filteredTargets.length}
          </span>
          {updatedLabel && (
            <span className="text-xs text-white-600 font-mono">
              · {updatedLabel}
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleDebugStore}
            title="Inspect bridge store"
            className="bg-dark-700 hover:bg-dark-600 border border-dark-600/60 text-yellow-400 hover:text-yellow-300 px-3 py-2 rounded-lg text-sm transition-colors font-mono"
          >
            🔍 Debug
          </button>
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={loading}
              title="Refresh targets"
              className="bg-dark-700 hover:bg-dark-600 disabled:opacity-40 border border-dark-600/60 text-white-300 hover:text-white px-3 py-2 rounded-lg text-sm transition-colors font-mono"
            >
              {loading ? "⟳ …" : "↺ Refresh"}
            </button>
          )}
          <input
            type="text"
            placeholder="Search targets..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-dark-800 border border-dark-600/60 rounded-lg px-3 py-2 text-sm text-white placeholder-dark-500 focus:outline-none focus:border-primary-500/60 focus:ring-1 focus:ring-primary-500/20 w-64 font-mono transition-all"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="bg-dark-700 hover:bg-dark-600 text-white-300 px-3 py-2 rounded-lg text-sm transition-colors"
            >
              ✕
            </button>
          )}
          <button
            onClick={() => navigate("/scans")}
            className="bg-primary-600 hover:bg-primary-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors"
          >
            + New Scan
          </button>
        </div>
      </div>
      {filteredTargets.length === 0 ? (
        searchQuery ? (
          <div className="text-center py-24 text-white-500">
            <Globe className="w-10 h-10 mx-auto mb-3 opacity-20" />
            <p className="text-sm font-mono">
              No targets matching "{searchQuery}"
            </p>
            <button
              onClick={() => setSearchQuery("")}
              className="mt-3 text-primary-400 hover:text-primary-300 text-xs font-mono"
            >
              Clear search
            </button>
          </div>
        ) : (
          <div className="text-center py-24 text-white-500">
            <Globe className="w-10 h-10 mx-auto mb-3 opacity-20" />
            <p className="text-sm font-mono mb-1">No targets imported yet</p>
            <p className="text-xs text-white-600 font-mono mb-4">
              Drop scan output files into{" "}
              <code className="text-cyan-500">imports/</code> or re-import
              previously processed files.
            </p>
            <div className="flex items-center justify-center gap-3">
              <button
                onClick={() => navigate("/scans")}
                className="bg-primary-600 hover:bg-primary-500 text-white px-4 py-2 rounded-lg text-xs font-semibold transition-colors"
              >
                Launch a Scan
              </button>
              <button
                onClick={handleReimport}
                disabled={reimporting}
                className="bg-dark-700 hover:bg-dark-600 disabled:opacity-40 border border-dark-600/60 text-white-300 hover:text-white px-4 py-2 rounded-lg text-xs font-mono transition-colors"
              >
                {reimporting
                  ? "⟳ Re-importing…"
                  : "↩ Re-import from processed/"}
              </button>
            </div>
          </div>
        )
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {filteredTargets.map((target) => (
            <div
              key={target.id}
              className="bg-dark-800 px-4 py-3 rounded-lg border border-dark-700 hover:border-dark-600 transition-colors cursor-pointer group"
              onClick={() => onSelectTarget(target)}
            >
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-3">
                  <Globe className="w-4 h-4 text-white-600 flex-shrink-0" />
                  <div>
                    <div className="text-sm font-semibold text-white group-hover:text-primary-300 transition-colors font-mono">
                      {target.domain}
                    </div>
                    <div className="text-xs text-white-500 mt-0.5 font-mono">
                      {target.programName}
                    </div>
                    <div className="flex gap-2 mt-2">
                      <span className="text-[13px] px-2 py-0.5 bg-dark-700 text-white-400 rounded font-mono border border-dark-600/40">
                        {target.subdomains?.length || 0} subs
                      </span>
                      <span className="text-[13px] px-2 py-0.5 bg-dark-700 text-white-400 rounded font-mono border border-dark-600/40">
                        {target.totalPorts} ports
                      </span>
                      {target.vulnerabilities?.length > 0 && (
                        <span className="text-[13px] px-2 py-0.5 bg-danger-500/10 text-danger-400 rounded font-mono border border-danger-500/20">
                          {target.vulnerabilities.length} vulns
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span
                    className={`text-[13px] px-2.5 py-1 rounded-md font-semibold font-mono ${
                      target.status === "RUNNING"
                        ? "badge-running"
                        : target.status === "COMPLETED"
                          ? "badge-completed"
                          : "badge-pending"
                    }`}
                  >
                    {target.status}
                  </span>
                  <ChevronRight className="w-4 h-4 text-white-600 group-hover:text-primary-400 transition-colors" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const TargetDetail = ({ target }: { target: Target }) => {
  // Determine scan type using the same helper
  const scanMetrics = getScanMetrics(target);
  const scanId = target.id?.toLowerCase() || "";
  const programName = target.programName?.toLowerCase() || "";
  const scanIdentifier = `${scanId} ${programName}`;

  // Determine which tabs to show based on scan type
  const isSubdomainScan =
    scanIdentifier.includes("amass") ||
    scanIdentifier.includes("subfinder") ||
    scanIdentifier.includes("assetfinder") ||
    scanIdentifier.includes("dnsx") ||
    scanIdentifier.includes("dnsgen") ||
    scanIdentifier.includes("shuffledns") ||
    scanIdentifier.includes("puredns");

  const isPortScan =
    scanIdentifier.includes("nmap") ||
    scanIdentifier.includes("masscan") ||
    scanIdentifier.includes("naabu") ||
    scanIdentifier.includes("rustscan");

  const isWebScan =
    scanIdentifier.includes("httpx") ||
    scanIdentifier.includes("httprobe") ||
    scanIdentifier.includes("gowitness") ||
    scanIdentifier.includes("aquatone") ||
    scanIdentifier.includes("webscreenshot");

  const isVulnScan =
    scanIdentifier.includes("nuclei") || scanIdentifier.includes("jaeles");

  const isWhoisScan = scanIdentifier.includes("whois");

  // Set default tab based on scan type
  const getDefaultTab = () => {
    if (isVulnScan) return "vulns";
    if (isPortScan) return "ports";
    if (isWebScan) return "websites";
    if (isWhoisScan) return "raw";
    return "subdomains";
  };

  const [activeTab, setActiveTab] = useState(getDefaultTab());
  const [showDownloadMenu, setShowDownloadMenu] = useState(false);
  const [vulnSevFilter, setVulnSevFilter] = useState("ALL");
  const [vulnSearch, setVulnSearch] = useState("");
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());
  const [webNameFilter, setWebNameFilter] = useState("");
  const [webPortFilter, setWebPortFilter] = useState("");
  const [webStatusFilter, setWebStatusFilter] = useState("");

  const toggleVulnExpand = (key: string) =>
    setExpandedVulns((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const SEV_ORDER: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  const filteredVulns = target.vulnerabilities
    .filter((v) => {
      if (
        vulnSevFilter !== "ALL" &&
        (v.severity as string)?.toUpperCase() !== vulnSevFilter
      )
        return false;
      if (vulnSearch) {
        const q = vulnSearch.toLowerCase();
        return (
          v.name?.toLowerCase().includes(q) ||
          v.path?.toLowerCase().includes(q) ||
          v.description?.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort(
      (a, b) =>
        (SEV_ORDER[a.severity as string] ?? 5) -
        (SEV_ORDER[b.severity as string] ?? 5),
    );

  const handleDownload = (format: "json" | "csv" | "txt" | "md") => {
    let content = "";
    let filename = `${target.domain}`;
    let mime = "text/plain";

    if (format === "json") {
      content = JSON.stringify(target, null, 2);
      filename += ".json";
      mime = "application/json";
    } else if (format === "md") {
      const vulnsToExport =
        activeTab === "vulns" ? filteredVulns : target.vulnerabilities;
      content =
        `# ${target.domain} — Vulnerabilities\n\n` +
        `*Exported ${new Date().toISOString()} — ${vulnsToExport.length} finding(s)*\n\n---\n\n` +
        vulnsToExport
          .map((v) => {
            const raw = (v as any).rawContent as string | undefined;
            if (raw && raw.trim().startsWith("#")) return raw.trim();
            return [
              `## [${v.severity}] ${v.name}`,
              ``,
              v.description ? `**Description**: ${v.description}` : null,
              v.path ? `**URL**: \`${v.path}\`` : null,
              raw ? `\n**Raw output**\n\`\`\`\n${raw.trim()}\n\`\`\`` : null,
              ``,
              `---`,
            ]
              .filter((l) => l !== null)
              .join("\n");
          })
          .join("\n\n");
      filename += "-vulns.md";
      mime = "text/markdown";
    } else if (format === "csv") {
      if (activeTab === "ports") {
        content =
          "hostname,ip,port,service\n" +
          target.subdomains
            .flatMap((s) =>
              s.ports.map(
                (p) =>
                  `"${s.hostname}","${s.ip || ""}",${p.port},"${p.service || "tcp"}"`,
              ),
            )
            .join("\n");
        filename += "-ports.csv";
      } else if (activeTab === "vulns") {
        content =
          "name,severity,description,path\n" +
          filteredVulns
            .map(
              (v) =>
                `"${v.name}","${v.severity}","${v.description}","${v.path || ""}"`,
            )
            .join("\n");
        filename += "-vulns.csv";
      } else {
        content =
          "hostname,ip,location\n" +
          target.subdomains
            .map((s) => `"${s.hostname}","${s.ip || ""}","${s.location || ""}"`)
            .join("\n");
        filename += "-subdomains.csv";
      }
      mime = "text/csv";
    } else {
      // txt
      if (activeTab === "ports") {
        content = target.subdomains
          .flatMap((s) => s.ports.map((p) => `${s.hostname}:${p.port}`))
          .join("\n");
        filename += "-ports.txt";
      } else if (activeTab === "vulns") {
        content = filteredVulns
          .map(
            (v) => `[${v.severity}] ${v.name}${v.path ? " - " + v.path : ""}`,
          )
          .join("\n");
        filename += "-vulns.txt";
      } else {
        content = target.subdomains.map((s) => s.hostname).join("\n");
        filename += "-hostnames.txt";
      }
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    setShowDownloadMenu(false);
  };

  // Collect unique gowitness bundle names from screenshot paths on the websites tab.
  // Screenshot paths are stored as /api/screenshots/{bundle_name}/screenshots/{fname}
  const gowitnessBundles =
    activeTab === "websites"
      ? [
          ...new Set(
            target.subdomains
              .filter((s) => s.screenshot?.startsWith("/api/screenshots/"))
              .map((s) => s.screenshot!.split("/")[3])
              .filter(Boolean),
          ),
        ]
      : [];

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="bg-dark-800 rounded-lg border border-dark-700 p-4">
        <div className="flex items-center gap-1.5 mb-3 text-xs font-mono">
          <Link
            to="/targets"
            className="text-white-500 hover:text-white-300 transition-colors"
          >
            targets
          </Link>
          <span className="text-white-700">/</span>
          <span className="text-white-300">{target.domain}</span>
        </div>
        <div className="flex justify-between items-start">
          <div>
            <div className="text-sm font-bold text-white font-mono flex items-center gap-2 flex-wrap">
              {target.domain}
              <span className="text-xs bg-dark-700 text-white-400 px-2 py-0.5 rounded font-mono border border-dark-700">
                {target.programName}
              </span>
              <div className="relative">
                <button
                  onClick={() => setShowDownloadMenu((v) => !v)}
                  className="text-xs bg-dark-700 hover:bg-dark-600 text-white-400 border border-dark-700 px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors font-mono"
                >
                  <Download className="w-3 h-3" /> Export
                  <ChevronDown className="w-3 h-3" />
                </button>
                {showDownloadMenu && (
                  <>
                    <div
                      className="fixed inset-0 z-10"
                      onClick={() => setShowDownloadMenu(false)}
                    />
                    <div className="absolute left-0 top-8 z-20 bg-dark-800 border border-dark-700 rounded-lg py-1 w-44 shadow-lg">
                      <div className="px-3 py-1.5 text-[13px] text-white-600 font-mono border-b border-dark-700 mb-1">
                        Export
                      </div>
                      <button
                        onClick={() => handleDownload("json")}
                        className="w-full text-left px-3 py-2 text-xs text-white-300 hover:bg-dark-700 hover:text-white transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-primary-400">{}</span> JSON — full
                        target
                      </button>
                      <button
                        onClick={() => handleDownload("csv")}
                        className="w-full text-left px-3 py-2 text-xs text-white-300 hover:bg-dark-700 hover:text-white transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-cyan-400">,</span> CSV —{" "}
                        {activeTab === "vulns"
                          ? "filtered vulns"
                          : "current tab"}
                      </button>
                      <button
                        onClick={() => handleDownload("txt")}
                        className="w-full text-left px-3 py-2 text-xs text-white-300 hover:bg-dark-700 hover:text-white transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-green-400">#</span> TXT —{" "}
                        {activeTab === "vulns" ? "filtered vulns" : "flat list"}
                      </button>
                      {/* Raw source files — always available */}

                      <a
                        href={`http://localhost:5000/api/targets/${encodeURIComponent(target.id)}/raw-zip`}
                        download
                        onClick={() => setShowDownloadMenu(false)}
                        className="w-full block px-3 py-2 text-xs text-white-300 hover:bg-dark-700 hover:text-white transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-yellow-400">📦</span> ZIP — raw
                        source
                      </a>

                      {activeTab === "vulns" && (
                        <button
                          onClick={() => handleDownload("md")}
                          className="w-full text-left px-3 py-2 text-xs text-white-300 hover:bg-dark-700 hover:text-white transition-colors font-mono flex items-center gap-2"
                        >
                          <div className="px-3 py-1.5 text-[13px] text-white-600 font-mono border-t border-dark-700 mt-1 mb-1">
                            Vulnerabilities
                          </div>
                          <span className="text-purple-400">M↓</span> Markdown —
                          raw reports
                        </button>
                      )}
                      {gowitnessBundles.length > 0 && (
                        <>
                          <div className="px-3 py-1.5 text-[13px] text-white-600 font-mono border-t border-dark-700 mt-1 mb-1">
                            GoWitness
                          </div>
                          {gowitnessBundles.map((bname) => (
                            <a
                              key={bname}
                              href={`http://localhost:5000/api/gowitness-bundle/${bname}/zip`}
                              download
                              onClick={() => setShowDownloadMenu(false)}
                              className="w-full block px-3 py-2 text-xs text-white-300 hover:bg-dark-700 hover:text-white transition-colors font-mono flex items-center gap-2"
                            >
                              <span className="text-white-400">🟪</span> ZIP —
                              {"gowitness format"}
                            </a>
                          ))}
                        </>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-lg font-bold text-white font-mono">
              {scanMetrics.count}
            </div>
            <div className="text-xs text-white-500 font-mono">
              {scanMetrics.label}
            </div>
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-0 border-b border-dark-700">
        {/* Subdomain tab */}
        {isSubdomainScan && (
          <button
            onClick={() => setActiveTab("subdomains")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono ${
              activeTab === "subdomains"
                ? "border-primary-500 text-primary-400"
                : "border-transparent text-white-500 hover:text-white-200"
            }`}
          >
            Subdomains ({target.subdomains.length})
          </button>
        )}
        {isWebScan && (
          <button
            onClick={() => setActiveTab("websites")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono ${
              activeTab === "websites"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-white-500 hover:text-white-200"
            }`}
          >
            Websites ({target.subdomains.length})
          </button>
        )}
        {isPortScan && (
          <button
            onClick={() => setActiveTab("ports")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono ${
              activeTab === "ports"
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-white-500 hover:text-white-200"
            }`}
          >
            Ports ({target.totalPorts})
          </button>
        )}
        {(isVulnScan || target.vulnerabilities.length > 0) && (
          <button
            onClick={() => setActiveTab("vulns")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono flex items-center gap-1.5 ${
              activeTab === "vulns"
                ? "border-danger-500 text-danger-400"
                : "border-transparent text-white-500 hover:text-white-200"
            }`}
          >
            Vulns
            {target.vulnerabilities.length > 0 && (
              <span className="bg-danger-500/20 text-danger-400 text-[9px] px-1.5 py-0.5 rounded font-bold">
                {target.vulnerabilities.length}
              </span>
            )}
          </button>
        )}
        {isWhoisScan && (
          <button
            onClick={() => setActiveTab("raw")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono ${
              activeTab === "raw"
                ? "border-primary-500 text-primary-400"
                : "border-transparent text-white-500 hover:text-white-200"
            }`}
          >
            Raw Output
          </button>
        )}
        {(isSubdomainScan || isPortScan) && (
          <button
            onClick={() => setActiveTab("map")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono ${
              activeTab === "map"
                ? "border-primary-500 text-primary-400"
                : "border-transparent text-white-500 hover:text-white-200"
            }`}
          >
            Topology
          </button>
        )}
      </div>

      {/* Subdomains view */}
      {activeTab === "subdomains" && (
        <div className="space-y-3">
          <div className="bg-dark-800/60 border border-dark-700/40 rounded-lg px-4 py-3">
            <p className="text-xs text-white-400 font-mono">
              💡 Run{" "}
              <code className="text-cyan-400 bg-dark-900 px-1.5 py-0.5 rounded">
                httpx
              </code>{" "}
              or{" "}
              <code className="text-cyan-400 bg-dark-900 px-1.5 py-0.5 rounded">
                gowitness
              </code>{" "}
              on these subdomains for HTTP probing &amp; screenshots.
            </p>
          </div>
          {target.subdomains.length === 0 ? (
            <div className="p-12 text-center text-white-600 bg-dark-800/40 rounded-lg border border-dark-700/40 border-dashed">
              <Globe className="w-8 h-8 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-mono">No subdomains found yet</p>
            </div>
          ) : (
            <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
              <table className="w-full text-left">
                <thead className="border-b border-dark-700">
                  <tr className="text-[13px] text-white-500 font-mono">
                    <th className="px-4 py-2.5 font-medium">IP</th>
                    <th className="px-4 py-2.5 font-medium">Location</th>
                  </tr>
                </thead>
                <tbody>
                  {target.subdomains.map((sub) => (
                    <tr
                      key={sub.id}
                      className="border-b border-dark-700/50 hover:bg-dark-700/20 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-sm text-cyan-300">
                        {sub.hostname}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-white-400">
                        {sub.ip || "—"}
                      </td>
                      <td className="px-4 py-3 text-xs text-white-500">
                        {sub.location || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Websites view */}
      {activeTab === "websites" && (
        <div className="space-y-4">
          {/* Filter bar */}
          <div className="flex flex-wrap gap-2 bg-dark-800 border border-dark-700 rounded-lg px-3 py-2.5 items-center">
            <Filter className="w-3.5 h-3.5 text-white-500 flex-shrink-0" />
            <input
              type="text"
              placeholder="Filter by name…"
              value={webNameFilter}
              onChange={(e) => setWebNameFilter(e.target.value)}
              className="bg-dark-700 border border-dark-600 rounded px-2.5 py-1 text-xs text-white font-mono placeholder-white-600 focus:outline-none focus:border-cyan-500 w-44"
            />
            <input
              type="text"
              placeholder="Filter by port (e.g. 443)"
              value={webPortFilter}
              onChange={(e) => setWebPortFilter(e.target.value)}
              className="bg-dark-700 border border-dark-600 rounded px-2.5 py-1 text-xs text-white font-mono placeholder-white-600 focus:outline-none focus:border-cyan-500 w-44"
            />
            <div className="flex items-center gap-1">
              {(["2xx", "3xx", "4xx", "5xx"] as const).map((range) => {
                const active = webStatusFilter === range;
                const colors: Record<string, string> = {
                  "2xx": active
                    ? "bg-emerald-600/30 border-emerald-500/60 text-emerald-300"
                    : "border-dark-600 text-white-500 hover:border-emerald-500/40 hover:text-emerald-400",
                  "3xx": active
                    ? "bg-yellow-600/30 border-yellow-500/60 text-yellow-300"
                    : "border-dark-600 text-white-500 hover:border-yellow-500/40 hover:text-yellow-400",
                  "4xx": active
                    ? "bg-red-600/30 border-red-500/60 text-red-300"
                    : "border-dark-600 text-white-500 hover:border-red-500/40 hover:text-red-400",
                  "5xx": active
                    ? "bg-purple-600/30 border-purple-500/60 text-purple-300"
                    : "border-dark-600 text-white-500 hover:border-purple-500/40 hover:text-purple-400",
                };
                return (
                  <button
                    key={range}
                    onClick={() => setWebStatusFilter(active ? "" : range)}
                    className={`px-2 py-1 text-[11px] font-mono rounded border transition-colors ${colors[range]}`}
                  >
                    {range}
                  </button>
                );
              })}
              <input
                type="text"
                placeholder="exact…"
                value={
                  ["2xx", "3xx", "4xx", "5xx"].includes(webStatusFilter)
                    ? ""
                    : webStatusFilter
                }
                onChange={(e) => setWebStatusFilter(e.target.value)}
                className="bg-dark-700 border border-dark-600 rounded px-2 py-1 text-xs text-white font-mono placeholder-white-600 focus:outline-none focus:border-cyan-500 w-16"
              />
            </div>
            {(webNameFilter || webPortFilter || webStatusFilter) && (
              <button
                onClick={() => {
                  setWebNameFilter("");
                  setWebPortFilter("");
                  setWebStatusFilter("");
                }}
                className="text-xs text-white-500 hover:text-white transition-colors font-mono flex items-center gap-1"
              >
                <X className="w-3 h-3" /> clear
              </button>
            )}
            <span className="ml-auto text-[11px] text-white-600 font-mono">
              {
                target.subdomains.filter((sub) => {
                  const nameOk =
                    !webNameFilter ||
                    sub.hostname
                      .toLowerCase()
                      .includes(webNameFilter.toLowerCase());
                  const portOk =
                    !webPortFilter ||
                    sub.ports.some((p) =>
                      String(p.port).includes(webPortFilter),
                    );
                  const _code = sub.statusCode ?? 0;
                  const statusOk =
                    !webStatusFilter ||
                    (webStatusFilter === "2xx"
                      ? _code >= 200 && _code < 300
                      : webStatusFilter === "3xx"
                        ? _code >= 300 && _code < 400
                        : webStatusFilter === "4xx"
                          ? _code >= 400 && _code < 500
                          : webStatusFilter === "5xx"
                            ? _code >= 500 && _code < 600
                            : String(_code).includes(webStatusFilter));
                  return nameOk && portOk && statusOk;
                }).length
              }{" "}
              / {target.subdomains.length} shown
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {target.subdomains
              .filter((sub) => {
                const nameOk =
                  !webNameFilter ||
                  sub.hostname
                    .toLowerCase()
                    .includes(webNameFilter.toLowerCase());
                const portOk =
                  !webPortFilter ||
                  sub.ports.some((p) => String(p.port).includes(webPortFilter));
                const _sc = sub.statusCode ?? 0;
                const statusOk =
                  !webStatusFilter ||
                  (webStatusFilter === "2xx"
                    ? _sc >= 200 && _sc < 300
                    : webStatusFilter === "3xx"
                      ? _sc >= 300 && _sc < 400
                      : webStatusFilter === "4xx"
                        ? _sc >= 400 && _sc < 500
                        : webStatusFilter === "5xx"
                          ? _sc >= 500 && _sc < 600
                          : String(_sc).includes(webStatusFilter));
                return nameOk && portOk && statusOk;
              })
              .map((sub) => {
                const statusCode = sub.statusCode ?? 0;
                const title = sub.title ?? "";
                const firstPort = sub.ports[0];
                // Screenshot path stored as relative /api/screenshots/... — prefix with bridge host
                const screenshotSrc = sub.screenshot
                  ? sub.screenshot.startsWith("/api/")
                    ? `http://localhost:5000${sub.screenshot}`
                    : sub.screenshot
                  : null;
                const statusColor =
                  statusCode >= 200 && statusCode < 300
                    ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10"
                    : statusCode >= 300 && statusCode < 400
                      ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10"
                      : statusCode >= 400
                        ? "text-red-400 border-red-500/30 bg-red-500/10"
                        : "text-white-400 border-dark-600/40 bg-dark-700/40";
                return (
                  <div
                    key={sub.id}
                    className="bg-dark-800 rounded-lg overflow-hidden border border-dark-700 hover:border-dark-600 transition-colors group card-hover"
                  >
                    <div className="h-70 bg-dark-900 relative">
                      {screenshotSrc ? (
                        <img
                          src={screenshotSrc}
                          alt={sub.hostname}
                          className="w-full h-full object-cover opacity-70 group-hover:opacity-100 transition-opacity"
                        />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center text-white-700">
                          <Globe className="w-7 h-7 opacity-30" />
                        </div>
                      )}
                    </div>
                    <div className="p-3">
                      {/* Hostname — clickable if url available */}
                      {sub.url ? (
                        <a
                          href={sub.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="block font-bold text-cyan-300 truncate text-sm mb-0.5 font-mono group-hover:text-primary-300 transition-colors hover:underline"
                          title={sub.url}
                        >
                          {sub.hostname}
                        </a>
                      ) : (
                        <h4
                          className="font-bold text-white truncate text-sm mb-0.5 font-mono group-hover:text-primary-300 transition-colors"
                          title={sub.hostname}
                        >
                          {sub.hostname}
                        </h4>
                      )}
                      {/* Page title */}
                      {title && (
                        <p
                          className="text-[14px] text-white-400 truncate mb-1.5 italic"
                          title={title}
                        >
                          {title}
                        </p>
                      )}
                      <div className="flex items-center gap-2 text-[14px] text-white-500 mb-2">
                        <span className="truncate max-w-[120px]">
                          {sub.location ||
                            (sub.ip !== sub.hostname ? sub.ip : "—")}
                        </span>
                      </div>
                      {sub.technologies.length > 0 && (
                        <div className="flex flex-wrap gap-1 mb-2">
                          {sub.technologies.slice(0, 4).map((tech) => (
                            <span
                              key={tech}
                              className="px-1.5 py-0.5 bg-dark-700 rounded text-[13px] text-white-400 border border-dark-600/30 font-mono"
                            >
                              {tech}
                            </span>
                          ))}
                          {sub.technologies.length > 4 && (
                            <span className="px-1.5 py-0.5 text-[13px] text-white-600 font-mono">
                              +{sub.technologies.length - 4}
                            </span>
                          )}
                        </div>
                      )}
                      <div className="flex flex-wrap gap-1">
                        {sub.ports.map((p) => (
                          <span
                            key={p.port}
                            className={`text-[13px] px-1.5 py-0.5 rounded border font-mono ${
                              p.service === "https" || p.port === 443
                                ? "border-cyan-500/30 text-cyan-400 bg-cyan-500/10"
                                : p.port === 80
                                  ? "border-success-500/30 text-success-400 bg-success-500/10"
                                  : "border-dark-600 text-white-500"
                            }`}
                          >
                            {p.port}/{p.service}
                          </span>
                        ))}
                        {/* Status code badge — top left */}
                        {statusCode > 0 && (
                          <div
                            className={`absolute top-1 px-1.5 py-0.5 rounded text-[13px] font-mono border ${statusColor}`}
                          >
                            {statusCode}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* Ports view */}
      {activeTab === "ports" && (
        <div className="space-y-3">
          {target.subdomains.length === 0 ? (
            <div className="p-12 text-center text-white-600 bg-dark-800/40 rounded-lg border border-dark-700/40 border-dashed">
              <Server className="w-8 h-8 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-mono">
                No hosts with open ports found
              </p>
            </div>
          ) : (
            target.subdomains.map((sub) =>
              sub.ports.length > 0 ? (
                <div
                  key={sub.id}
                  className="bg-dark-800 rounded-lg border border-dark-700 p-4"
                >
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <h4 className="font-bold text-white text-sm font-mono">
                        {sub.hostname}
                      </h4>
                      {sub.ip && (
                        <p className="text-[13px] text-white-500 font-mono mt-0.5">
                          {sub.ip}
                        </p>
                      )}
                    </div>
                    <span className="text-[14px] bg-primary-500/10 text-primary-400 px-2 py-1 rounded border border-primary-500/20 font-mono">
                      {sub.ports.length} open ports
                    </span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                    {sub.ports.map((p, pi) => {
                      // Normalise: bridge may store Port objects OR legacy plain strings
                      const portNum =
                        typeof p === "object" ? p.port : Number(p);
                      const svcName =
                        typeof p === "object" ? p.service || "tcp" : "tcp";
                      // isOpen: true for objects that say so, or treat any entry as open
                      const isOpen =
                        typeof p === "object" ? p.isOpen !== false : true;
                      return (
                        <div
                          key={`${portNum}-${pi}`}
                          className="bg-dark-900 rounded-lg border border-dark-700/60 p-2.5"
                        >
                          <div className="font-mono text-sm text-white">
                            {portNum}
                            <span className="text-white-600">/{svcName}</span>
                          </div>
                          <div
                            className={`text-[13px] mt-0.5 font-mono ${isOpen ? "text-success-400" : "text-danger-400"}`}
                          >
                            {isOpen ? "open" : "closed"}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : null,
            )
          )}
        </div>
      )}

      {/* Vulnerabilities view */}
      {activeTab === "vulns" && (
        <div className="space-y-3">
          {/* Severity filter + search */}
          <div className="flex flex-col sm:flex-row gap-2 flex-wrap">
            <div className="flex flex-wrap gap-1.5">
              {(
                ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const
              ).map((sev) => {
                const cnt =
                  sev === "ALL"
                    ? target.vulnerabilities.length
                    : target.vulnerabilities.filter(
                        (v) => (v.severity as string)?.toUpperCase() === sev,
                      ).length;
                const active = vulnSevFilter === sev;
                const colorActive =
                  sev === "ALL"
                    ? "bg-primary-500/20 border-primary-500/40 text-primary-300"
                    : sev === "CRITICAL"
                      ? "bg-danger-500/20 border-danger-500/40 text-danger-300"
                      : sev === "HIGH"
                        ? "bg-orange-500/20 border-orange-500/40 text-orange-300"
                        : sev === "MEDIUM"
                          ? "bg-warn-500/20 border-warn-500/40 text-warn-300"
                          : sev === "LOW"
                            ? "bg-success-500/20 border-success-500/40 text-success-300"
                            : "bg-cyan-500/20 border-cyan-500/40 text-cyan-300";
                return (
                  <button
                    key={sev}
                    onClick={() => setVulnSevFilter(sev)}
                    className={`px-2.5 py-1 rounded border text-[13px] font-mono font-semibold transition-colors ${
                      active
                        ? colorActive
                        : "bg-dark-800 border-dark-700 text-white-400 hover:border-dark-600 hover:text-white"
                    }`}
                  >
                    {sev}
                    {cnt > 0 && (
                      <span className="ml-1 opacity-70 font-normal">
                        ({cnt})
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
            <input
              type="text"
              value={vulnSearch}
              onChange={(e) => setVulnSearch(e.target.value)}
              placeholder="Search name, path…"
              className="flex-1 sm:max-w-xs bg-dark-800 border border-dark-700 rounded px-3 py-1.5 text-[13px] text-white-200 font-mono placeholder-white-600 focus:outline-none focus:border-primary-500/50"
            />
          </div>

          {filteredVulns.length === 0 ? (
            <div className="p-12 text-center text-white-600 bg-dark-800/40 rounded-lg border border-dark-700/40 border-dashed">
              <ShieldAlert className="w-8 h-8 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-mono">No vulnerabilities match</p>
            </div>
          ) : (
            filteredVulns.map((vuln, idx) => {
              const key = `${vuln.id}:${vuln.path}:${idx}`;
              const expanded = expandedVulns.has(key);
              const rawContent = (vuln as any).rawContent as string | undefined;
              return (
                <div
                  key={key}
                  className={`bg-dark-800 rounded-lg border border-dark-700 ${
                    (vuln.severity as string) === "CRITICAL"
                      ? "severity-critical"
                      : (vuln.severity as string) === "HIGH"
                        ? "severity-high"
                        : (vuln.severity as string) === "MEDIUM"
                          ? "severity-medium"
                          : (vuln.severity as string) === "LOW"
                            ? "severity-low"
                            : "severity-info"
                  }`}
                >
                  <div className="p-4 flex justify-between items-start">
                    <div className="pl-2 flex-1 min-w-0">
                      <h4 className="text-white font-semibold text-sm flex items-center gap-2 flex-wrap">
                        {vuln.name}
                        <span
                          className={`text-[13px] font-bold px-2 py-0.5 rounded uppercase font-mono ${
                            (vuln.severity as string) === "CRITICAL"
                              ? "bg-danger-500/20 text-danger-400"
                              : (vuln.severity as string) === "HIGH"
                                ? "bg-orange-500/20 text-orange-400"
                                : (vuln.severity as string) === "MEDIUM"
                                  ? "bg-warn-500/20 text-warn-400"
                                  : (vuln.severity as string) === "LOW"
                                    ? "bg-success-500/20 text-success-400"
                                    : "bg-cyan-500/20 text-cyan-400"
                          }`}
                        >
                          {vuln.severity}
                        </span>
                      </h4>
                      {vuln.description && (
                        <p className="text-white-400 text-xs mt-1.5">
                          {vuln.description}
                        </p>
                      )}
                      {vuln.path && (
                        <p className="text-white-500 text-[13px] font-mono mt-2 bg-dark-900 inline-block px-2 py-1 rounded border border-dark-700/40 break-all">
                          {vuln.path}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-1 ml-3 flex-shrink-0">
                      <button
                        onClick={() =>
                          navigator.clipboard.writeText(
                            rawContent ||
                              `[${vuln.severity}] ${vuln.name}\n${vuln.path || ""}`,
                          )
                        }
                        title="Copy to clipboard"
                        className="p-1.5 text-white-600 hover:text-white-300 transition-colors"
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                      {rawContent && (
                        <button
                          onClick={() => toggleVulnExpand(key)}
                          title={expanded ? "Collapse raw" : "Show raw output"}
                          className={`p-1.5 transition-colors ${
                            expanded
                              ? "text-primary-400"
                              : "text-white-600 hover:text-white-300"
                          }`}
                        >
                          <ChevronDown
                            className={`w-3.5 h-3.5 transition-transform ${
                              expanded ? "rotate-180" : ""
                            }`}
                          />
                        </button>
                      )}
                    </div>
                  </div>
                  {expanded && rawContent && (
                    <div className="border-t border-dark-700 px-4 py-3 bg-dark-900/40 rounded-b-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[13px] text-white-500 font-mono">
                          Raw output
                        </span>
                        <button
                          onClick={() =>
                            navigator.clipboard.writeText(rawContent)
                          }
                          className="text-[13px] text-white-500 hover:text-primary-400 transition-colors font-mono flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" /> Copy raw
                        </button>
                      </div>
                      <pre className="text-xs text-white-300 font-mono whitespace-pre-wrap leading-relaxed bg-dark-900 rounded border border-dark-700 p-3 overflow-x-auto max-h-96">
                        {rawContent}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Raw output */}
      {activeTab === "raw" && (
        <div className="space-y-4">
          {(target as any).rawWhoisData &&
          Object.keys((target as any).rawWhoisData).length > 0 ? (
            Object.entries(
              (target as any).rawWhoisData as Record<string, string>,
            ).map(([domain, text]) => (
              <div key={domain}>
                <div className="flex items-center gap-2 mb-1.5 px-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 flex-shrink-0" />
                  <span className="text-xs font-mono font-semibold text-cyan-400">
                    {domain}
                  </span>
                </div>
                <div className="bg-dark-900 rounded-lg border border-dark-700 p-4 overflow-x-auto">
                  <pre className="text-xs text-white-300 font-mono whitespace-pre-wrap leading-relaxed">
                    {text}
                  </pre>
                </div>
              </div>
            ))
          ) : (
            <div className="bg-dark-900 rounded-lg border border-dark-700 p-4">
              <pre className="text-xs text-cyan-300 font-mono whitespace-pre-wrap leading-relaxed">
                {target.subdomains.length > 0
                  ? target.subdomains.map((s) => s.hostname).join("\n")
                  : "No output available"}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Topology map */}
      {activeTab === "map" && (
        <div className="bg-dark-800 p-4 rounded-lg border border-dark-700 min-h-[400px]">
          <TopologyGraph target={target} />
        </div>
      )}
    </div>
  );
};

// ------------- Layout -------------

const Sidebar = () => {
  const location = useLocation();
  const [expandedGroups, setExpandedGroups] = useState<string[]>(() =>
    location.pathname.startsWith("/scans") ? ["scans"] : [],
  );

  useEffect(() => {
    if (
      location.pathname.startsWith("/scans") &&
      !expandedGroups.includes("scans")
    ) {
      setExpandedGroups((prev) => [...prev, "scans"]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  const toggleGroup = (key: string) =>
    setExpandedGroups((prev) =>
      prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key],
    );

  const isActiveLink = (path: string) =>
    location.pathname === path ||
    (path !== "/" && location.pathname.startsWith(path));

  const NavLink = ({
    to,
    icon: Icon,
    label,
    badge,
  }: {
    to: string;
    icon: any;
    label: string;
    badge?: string;
  }) => {
    const active = isActiveLink(to);
    return (
      <Link
        to={to}
        className={`flex items-center gap-2.5 px-2.5 py-2 rounded transition-colors mb-0.5 ${
          active
            ? "nav-active text-primary-300"
            : "text-white-400 hover:bg-dark-700/50 hover:text-white"
        }`}
      >
        <Icon size={16} className="flex-shrink-0" />
        <span className="text-[15px] flex-1">{label}</span>
        {badge && (
          <span className="text-[13px] font-bold bg-danger-500/20 text-danger-400 px-1.5 py-0.5 rounded font-mono">
            {badge}
          </span>
        )}
      </Link>
    );
  };

  const NavGroup = ({
    groupKey,
    icon: Icon,
    label,
    children,
  }: {
    groupKey: string;
    icon: any;
    label: string;
    children: React.ReactNode;
  }) => {
    const expanded = expandedGroups.includes(groupKey);
    const anyChildActive = location.pathname.startsWith(`/${groupKey}`);
    return (
      <div>
        <button
          onClick={() => toggleGroup(groupKey)}
          className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded transition-colors mb-0.5 ${
            anyChildActive
              ? "nav-active text-primary-300"
              : "text-white-400 hover:bg-dark-700/50 hover:text-white"
          }`}
        >
          <Icon size={16} className="flex-shrink-0" />
          <span className="text-[15px] flex-1 text-left">{label}</span>
          <ChevronDown
            size={13}
            className={`text-white-500 transition-transform flex-shrink-0 ${
              expanded ? "rotate-180" : ""
            }`}
          />
        </button>
        {expanded && (
          <div className="ml-4 pl-3 border-l border-dark-700/60 mb-1 space-y-0.5">
            {children}
          </div>
        )}
      </div>
    );
  };

  const SubLink = ({ to, label }: { to: string; label: string }) => {
    const [basePath, qs] = to.split("?");
    const qsKey = qs?.split("=")[0];
    const qsVal = qs?.split("=")[1];
    const active =
      location.pathname === basePath &&
      (!qs || location.search.includes(`${qsKey}=${qsVal}`));
    return (
      <Link
        to={to}
        className={`flex items-center gap-2 px-2.5 py-1.5 rounded-md text-[13px] transition-colors ${
          active
            ? "text-primary-300 bg-primary-500/10"
            : "text-white-500 hover:text-white hover:bg-dark-700/40"
        }`}
      >
        <span
          className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
            active ? "bg-primary-400" : "bg-dark-600"
          }`}
        />
        {label}
      </Link>
    );
  };

  return (
    <div className="w-56 sidebar-glow border-r border-dark-700 h-screen fixed left-0 top-0 flex flex-col z-30">
      {/* Logo */}
      <div className="px-4 pt-4 pb-3 flex items-center gap-2.5 border-b border-dark-700">
        <BinocularsSkullLogo size={32} />
        <div>
          <div className="text-[16px] font-bold text-white leading-none tracking-wide">
            AXIOM<span className="text-primary-400">DASH</span>
          </div>
          <div className="text-[13px] text-white-500 font-mono mt-0.5">
            Recon Platform
          </div>
        </div>
      </div>

      {/* Nav */}
      <div className="flex-1 px-2 py-3 space-y-4 overflow-y-auto">
        <div>
          <p className="text-[11px] uppercase tracking-widest text-white-600 font-mono mb-2 px-2.5">
            Recon
          </p>
          <NavLink to="/" icon={LayoutDashboard} label="Dashboard" />
          <NavLink to="/targets" icon={TargetIcon} label="Targets" />
          <NavLink to="/vulns" icon={ShieldAlert} label="Vulnerabilities" />
          <NavGroup groupKey="scans" icon={Activity} label="Scans">
            <SubLink to="/scans?tab=launcher" label="Launch Scan" />
            <SubLink to="/scans?tab=active" label="Active / Monitor" />
            <SubLink to="/scans?tab=output" label="Output Viewer" />
          </NavGroup>
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-widest text-white-600 font-mono mb-2 px-2.5">
            Infrastructure
          </p>
          <NavLink to="/fleet" icon={Server} label="Fleet" />
          <NavLink to="/settings" icon={SettingsIcon} label="Settings" />
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-widest text-white-600 font-mono mb-2 px-2.5">
            Help
          </p>
          <NavLink to="/docs" icon={BookOpen} label="Documentation" />
        </div>
      </div>
    </div>
  );
};

const Header = ({
  unreadCount = 0,
  onBellClick,
}: {
  unreadCount?: number;
  onBellClick?: () => void;
}) => {
  const location = useLocation();
  const pageLabels: Record<string, string> = {
    "/": "Dashboard",
    "/targets": "Targets",
    "/vulns": "Vulnerabilities",
    "/scans": "Scans",
    "/fleet": "Fleet",
    "/docs": "Documentation",
    "/settings": "Settings",
  };
  const currentPage = Object.entries(pageLabels).find(([path]) =>
    path === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(path),
  );
  const pageTitle = currentPage?.[1] ?? "Dashboard";

  return (
    <header className="h-12 bg-dark-900 border-b border-dark-700 sticky top-0 z-20 flex items-center justify-between px-5 ml-56">
      {/* Left: breadcrumb */}
      <div className="flex items-center gap-1.5 text-sm">
        <span className="text-white-600 font-mono text-xs">axiom /</span>
        <span className="text-white-200 text-xs font-mono">{pageTitle}</span>
      </div>

      {/* Right: status + actions */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-success-400"></span>
          <span className="text-success-400 text-xs font-mono">online</span>
        </div>
        <div className="h-4 w-px bg-dark-700" />
        <button
          onClick={onBellClick}
          className="relative p-1.5 text-white-500 hover:text-white transition-colors"
        >
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-3.5 bg-danger-500 rounded text-[9px] font-bold text-white flex items-center justify-center px-1 font-mono">
              {unreadCount > 9 ? "9+" : unreadCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
};

// ------------- Main App Wrapper -------------

// ──────────────────────────────────────────────────────────────────────────────
// All-Vulnerabilities page
// ──────────────────────────────────────────────────────────────────────────────
const VulnsPage = ({ targets }: { targets: Target[] }) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const sevParam = searchParams.get("sev")?.toUpperCase() || "ALL";
  const [sevFilter, setSevFilter] = useState(sevParam);
  const [searchQ, setSearchQ] = useState("");
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  // Keep state in sync when URL param changes (e.g. dashboard card click)
  useEffect(() => {
    setSevFilter(searchParams.get("sev")?.toUpperCase() || "ALL");
  }, [searchParams]);

  // Flatten all vulns from every target
  const allVulns = targets.flatMap((target) =>
    (target.vulnerabilities || []).map((v) => ({
      ...v,
      targetDomain: target.domain,
      targetId: target.id,
    })),
  );

  const SEVERITIES = [
    "ALL",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
  ] as const;
  const SEV_ORDER: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  const sevCount = (sev: string) =>
    sev === "ALL"
      ? allVulns.length
      : allVulns.filter((v) => (v.severity as string)?.toUpperCase() === sev)
          .length;

  const filtered = allVulns
    .filter((v) => {
      if (
        sevFilter !== "ALL" &&
        (v.severity as string)?.toUpperCase() !== sevFilter
      )
        return false;
      if (searchQ) {
        const q = searchQ.toLowerCase();
        return (
          v.name?.toLowerCase().includes(q) ||
          v.path?.toLowerCase().includes(q) ||
          (v as any).targetDomain?.toLowerCase().includes(q) ||
          v.description?.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort(
      (a, b) =>
        (SEV_ORDER[(a.severity as string)?.toUpperCase()] ?? 5) -
        (SEV_ORDER[(b.severity as string)?.toUpperCase()] ?? 5),
    );

  const toggleExpand = (key: string) =>
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const sevBadgeClass = (sev: string) => {
    switch ((sev as string)?.toUpperCase()) {
      case "CRITICAL":
        return "bg-danger-500/20 text-danger-400 border-danger-500/30";
      case "HIGH":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "MEDIUM":
        return "bg-warn-500/20 text-warn-400 border-warn-500/30";
      case "LOW":
        return "bg-success-500/20 text-success-400 border-success-500/30";
      default:
        return "bg-cyan-500/20 text-cyan-400 border-cyan-500/30";
    }
  };

  const sevButtonClass = (sev: string, active: boolean) => {
    if (!active)
      return "bg-dark-800 border-dark-700 text-white-400 hover:border-dark-600 hover:text-white";
    switch (sev) {
      case "ALL":
        return "bg-primary-500/20 border-primary-500/40 text-primary-300";
      case "CRITICAL":
        return "bg-danger-500/20 border-danger-500/40 text-danger-300";
      case "HIGH":
        return "bg-orange-500/20 border-orange-500/40 text-orange-300";
      case "MEDIUM":
        return "bg-warn-500/20 border-warn-500/40 text-warn-300";
      case "LOW":
        return "bg-success-500/20 border-success-500/40 text-success-300";
      default:
        return "bg-cyan-500/20 border-cyan-500/40 text-cyan-300";
    }
  };

  const affectedTargets = targets.filter(
    (t) => (t.vulnerabilities || []).length > 0,
  ).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-white font-mono flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-danger-400" />
            Vulnerabilities
          </h1>
          <p className="text-[13px] text-white-500 font-mono mt-0.5">
            {filtered.length} finding{filtered.length !== 1 ? "s" : ""} across{" "}
            {affectedTargets} target{affectedTargets !== 1 ? "s" : ""}
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-2 flex-wrap">
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((sev) => (
            <button
              key={sev}
              onClick={() => {
                setSevFilter(sev);
                setSearchParams(sev === "ALL" ? {} : { sev });
              }}
              className={`px-2.5 py-1 rounded border text-[13px] font-mono font-semibold transition-colors ${sevButtonClass(
                sev,
                sevFilter === sev,
              )}`}
            >
              {sev}
              <span className="ml-1 opacity-60 font-normal">
                ({sevCount(sev)})
              </span>
            </button>
          ))}
        </div>
        <div className="flex-1 sm:max-w-xs">
          <input
            type="text"
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
            placeholder="Search findings, paths, targets…"
            className="w-full bg-dark-800 border border-dark-700 rounded px-3 py-1.5 text-[13px] text-white-200 font-mono placeholder-white-600 focus:outline-none focus:border-primary-500/50"
          />
        </div>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center text-white-600 bg-dark-800/40 rounded-lg border border-dark-700/40 border-dashed">
          <ShieldAlert className="w-8 h-8 mx-auto mb-3 opacity-20" />
          <p className="text-sm font-mono">No vulnerabilities match</p>
        </div>
      ) : (
        <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
          <table className="w-full text-left">
            <thead className="border-b border-dark-700">
              <tr className="text-[13px] text-white-500 font-mono">
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Finding</th>
                <th className="px-4 py-2.5 font-medium w-28">Severity</th>
                <th className="px-4 py-2.5 font-medium">Path / URL</th>
                <th className="px-4 py-2.5 font-medium w-16"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((vuln, idx) => {
                const key = `${(vuln as any).targetId}:${vuln.id}:${vuln.path}:${idx}`;
                const expanded = expandedKeys.has(key);
                const rawContent = (vuln as any).rawContent as
                  | string
                  | undefined;
                return (
                  <React.Fragment key={key}>
                    <tr className="border-b border-dark-700/50 hover:bg-dark-700/20 transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-cyan-400">
                        <Link
                          to={`/targets/${(vuln as any).targetId}`}
                          className="hover:underline"
                        >
                          {(vuln as any).targetDomain}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-sm text-white max-w-xs">
                        <div className="font-medium truncate" title={vuln.name}>
                          {vuln.name}
                        </div>
                        {vuln.description && (
                          <div
                            className="text-xs text-white-500 font-mono mt-0.5 truncate"
                            title={vuln.description}
                          >
                            {vuln.description}
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`text-[13px] font-bold px-2 py-0.5 rounded border font-mono ${sevBadgeClass(
                            vuln.severity as string,
                          )}`}
                        >
                          {(vuln.severity as string) || "INFO"}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-white-400 max-w-xs">
                        <div className="truncate" title={vuln.path}>
                          {vuln.path || "—"}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() =>
                              navigator.clipboard.writeText(
                                rawContent ||
                                  `[${vuln.severity}] ${vuln.name}\n${vuln.path || ""}`,
                              )
                            }
                            title="Copy"
                            className="p-1 text-white-600 hover:text-white-300 transition-colors"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                          {rawContent && (
                            <button
                              onClick={() => toggleExpand(key)}
                              title={expanded ? "Collapse" : "Show raw"}
                              className={`p-1 transition-colors ${
                                expanded
                                  ? "text-primary-400"
                                  : "text-white-600 hover:text-white-300"
                              }`}
                            >
                              <ChevronDown
                                className={`w-3.5 h-3.5 transition-transform ${
                                  expanded ? "rotate-180" : ""
                                }`}
                              />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expanded && rawContent && (
                      <tr className="border-b border-dark-700/50 bg-dark-900/60">
                        <td colSpan={5} className="px-4 py-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-[13px] text-white-500 font-mono">
                              Raw output
                            </span>
                            <button
                              onClick={() =>
                                navigator.clipboard.writeText(rawContent)
                              }
                              className="text-[13px] text-white-500 hover:text-primary-400 transition-colors font-mono flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" /> Copy raw
                            </button>
                          </div>
                          <pre className="text-xs text-white-300 font-mono whitespace-pre-wrap leading-relaxed bg-dark-900 rounded border border-dark-700 p-3 overflow-x-auto max-h-96">
                            {rawContent}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const ScansPage = ({ onTargetsRefresh }: { onTargetsRefresh: () => void }) => {
  const [searchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const [activeTab, setActiveTab] = useState<"launcher" | "active" | "output">(
    () => {
      if (tabParam === "active") return "active";
      if (tabParam === "output") return "output";
      return "launcher";
    },
  );
  const [selectedScanId, setSelectedScanId] = useState<string | undefined>();

  useEffect(() => {
    if (tabParam === "active") setActiveTab("active");
    else if (tabParam === "output") setActiveTab("output");
    else if (tabParam === "launcher") setActiveTab("launcher");
  }, [tabParam]);

  const handleScanLaunched = (scanId: string) => {
    console.log("Scan launched:", scanId);
    onTargetsRefresh();
    setActiveTab("active"); // Switch to active scans after launching
  };

  const handleScanSelected = (scanId: string) => {
    setSelectedScanId(scanId);
    setActiveTab("output");
  };

  return (
    <div className="space-y-4">
      {/* Tabs */}
      <div className="flex gap-0 border-b border-dark-700">
        <button
          onClick={() => setActiveTab("launcher")}
          className={`px-4 py-2.5 text-xs font-mono border-b-2 transition-colors ${
            activeTab === "launcher"
              ? "border-primary-500 text-white"
              : "border-transparent text-white-500 hover:text-white-300"
          }`}
        >
          Launch Scan
        </button>
        <button
          onClick={() => setActiveTab("active")}
          className={`px-4 py-2.5 text-xs font-mono border-b-2 transition-colors ${
            activeTab === "active"
              ? "border-primary-500 text-white"
              : "border-transparent text-white-500 hover:text-white-300"
          }`}
        >
          Active Scans
        </button>
        <button
          onClick={() => setActiveTab("output")}
          className={`px-4 py-2.5 text-xs font-mono border-b-2 transition-colors ${
            activeTab === "output"
              ? "border-primary-500 text-white"
              : "border-transparent text-white-500 hover:text-white-300"
          }`}
        >
          Output Viewer
        </button>
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === "launcher" && (
          <ScanLauncher
            apiUrl="http://localhost:5000"
            onScanLaunched={handleScanLaunched}
          />
        )}

        {activeTab === "active" && (
          <ActiveScans
            apiUrl="http://localhost:5000"
            onScanSelected={handleScanSelected}
          />
        )}

        {activeTab === "output" && (
          <ScanOutput apiUrl="http://localhost:5000" scanId={selectedScanId} />
        )}
      </div>
    </div>
  );
};

const FleetControlPage = ({
  onNotify,
}: {
  onNotify?: (type: string, title: string, message: string) => void;
}) => {
  const [fleet, setFleet] = useState<FleetInstance[]>([]);
  const [loading, setLoading] = useState(false);
  const [filterMode, setFilterMode] = useState("managed"); // "managed", "all", or "prefix"
  const [customPrefix, setCustomPrefix] = useState("");
  const [hiddenIds, setHiddenIds] = useState<Set<string>>(new Set());

  const effectiveFilter =
    filterMode === "prefix" ? customPrefix.trim() || "managed" : filterMode;

  const loadFleet = async (forceRefresh = false) => {
    setLoading(true);
    try {
      const data = await fetchFleet(forceRefresh, effectiveFilter);
      setFleet(data);
      // Prune hiddenIds: remove any IDs that no longer exist in the fleet
      const liveIds = new Set(data.map((f: FleetInstance) => f.id));
      setHiddenIds((prev) => {
        const pruned = new Set([...prev].filter((id) => liveIds.has(id)));
        return pruned.size !== prev.size ? pruned : prev;
      });
    } catch (error) {
      console.warn("Failed to load fleet:", error);
    } finally {
      setLoading(false);
    }
  };

  const hideInstance = (id: string) => {
    setHiddenIds((prev) => new Set([...prev, id]));
  };

  const visibleFleet = fleet.filter((f) => !hiddenIds.has(f.id));
  const hiddenCount = hiddenIds.size;

  useEffect(() => {
    loadFleet();
  }, [filterMode, customPrefix]);

  // Auto-refresh every 30 s while the fleet page is open so --rm-when-done
  // deletions (triggered by axiom-scan finishing) show up without a manual refresh.
  useEffect(() => {
    const interval = setInterval(() => loadFleet(true), 30_000);
    return () => clearInterval(interval);
  }, [filterMode, customPrefix]);

  // When a scan is launched with --rm-when-done, poll more aggressively for a
  // while so the deleted instances disappear from the list shortly after the
  // scan completes, without any manual action.
  useEffect(() => {
    const handler = (e: Event) => {
      const { rmWhenDone: rwd, fleetPrefix: fp } =
        (e as CustomEvent).detail ?? {};
      if (!rwd) return; // only care about rm-when-done scans
      // Poll every 15 s for 20 minutes — axiom-scan can take a while.
      let ticks = 0;
      const MAX_TICKS = 80; // 80 × 15 s = 20 min
      const id = setInterval(() => {
        loadFleet(true);
        if (++ticks >= MAX_TICKS) clearInterval(id);
      }, 15_000);
    };
    window.addEventListener("axiom:scan-launched", handler);
    return () => window.removeEventListener("axiom:scan-launched", handler);
  }, [filterMode, customPrefix]);

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center flex-wrap gap-2">
        <span className="text-sm font-semibold text-white-300 font-mono">
          Fleet
          {hiddenCount > 0 && (
            <button
              onClick={() => setHiddenIds(new Set())}
              className="ml-3 text-[13px] text-white-500 hover:text-white-300 font-mono transition-colors"
              title="Show hidden instances"
            >
              ({hiddenCount} hidden — show all)
            </button>
          )}
        </span>
        <div className="flex gap-2 items-center flex-wrap">
          <select
            value={filterMode}
            onChange={(e) => {
              setFilterMode(e.target.value);
              if (e.target.value !== "prefix") setCustomPrefix("");
            }}
            className="bg-dark-800 text-white-200 border border-dark-600 px-3 py-1.5 rounded-lg text-[13px] font-mono focus:outline-none focus:border-primary-500 transition-colors"
          >
            <option value="managed">Axiom managed</option>
            <option value="all">All instances</option>
            <option value="prefix">By name prefix…</option>
          </select>
          {filterMode === "prefix" && (
            <input
              type="text"
              value={customPrefix}
              onChange={(e) => setCustomPrefix(e.target.value)}
              placeholder="e.g. dns01"
              className="bg-dark-800 text-white border border-dark-600 px-3 py-1.5 rounded-lg text-[13px] font-mono w-32 focus:outline-none focus:border-primary-500 transition-colors placeholder:text-white-600"
            />
          )}
          <button
            onClick={() => loadFleet(true)}
            disabled={loading}
            className="bg-dark-700 hover:bg-dark-600 disabled:opacity-50 text-white-300 hover:text-white border border-dark-600 px-3 py-1.5 rounded-lg text-[13px] font-mono transition-colors"
          >
            {loading ? "Refreshing…" : "↺ Refresh"}
          </button>
        </div>
      </div>
      {loading && fleet.length === 0 ? (
        <div className="text-center text-white-500 py-20 font-mono text-[13px]">
          Fetching fleet data…
        </div>
      ) : (
        <FleetControl
          apiUrl="http://localhost:5000"
          fleet={visibleFleet}
          onRefresh={() => loadFleet(true)}
          onNotify={onNotify}
          onHide={hideInstance}
        />
      )}
    </div>
  );
};

// ── Docs Page ──────────────────────────────────────
const DocsPage = () => {
  const [activeSection, setActiveSection] = useState("quickstart");
  const sections = [
    { id: "quickstart", label: "Quick Start" },
    { id: "modules", label: "Scan Modules" },
    { id: "dashboard", label: "Dashboard Guide" },
    { id: "importing", label: "Importing Results" },
    { id: "fleet", label: "Fleet Management" },
    { id: "notifications", label: "Notifications" },
  ];
  const moduleData = [
    {
      name: "amass",
      type: "Subdomain Enum",
      fmt: "TXT, JSON",
      desc: "Passive & active subdomain enumeration. One domain per line or JSON array.",
    },
    {
      name: "dnsx",
      type: "DNS Resolution",
      fmt: "TXT, JSON, JSONL",
      desc: "Resolves subdomains, validates DNS records. Output: resolved hostnames.",
    },
    {
      name: "subfinder",
      type: "Subdomain Enum",
      fmt: "TXT",
      desc: "Fast passive subdomain discovery via multiple APIs.",
    },
    {
      name: "httpx",
      type: "HTTP Probe",
      fmt: "TXT, JSON, JSONL",
      desc: "Probes hosts for live HTTP/S services. Returns live URLs and tech stack.",
    },
    {
      name: "nmap",
      type: "Port Scan",
      fmt: "XML",
      desc: "Network port scanner and service detection. Open ports, banners.",
    },
    {
      name: "masscan",
      type: "Port Scan",
      fmt: "XML",
      desc: "Ultra-fast port scanner. Best for large IP ranges.",
    },
    {
      name: "nuclei",
      type: "Vulnerability",
      fmt: "JSONL, TXT",
      desc: "Template-based vulnerability scanner. Finds CVEs, misconfigs, exposures.",
    },
    {
      name: "gowitness",
      type: "Screenshots",
      fmt: "SQLite, JSON, TXT",
      desc: "Web screenshot capture. SQLite database is auto-imported.",
    },
    {
      name: "ffuf",
      type: "Fuzzing",
      fmt: "JSON, TXT",
      desc: "Fast web fuzzer for directories, files, and parameters.",
    },
    {
      name: "whois",
      type: "WHOIS Lookup",
      fmt: "TXT",
      desc: "Domain registration data. Country codes map to the geo map.",
    },
    {
      name: "assetfinder",
      type: "Subdomain Enum",
      fmt: "TXT",
      desc: "Fast subdomain discovery from Tomnomnom.",
    },
  ];
  const C = ({ v }: { v: string }) => (
    <code className="bg-dark-900 border border-dark-700 rounded px-1.5 py-0.5 text-cyan-400 text-xs font-mono">
      {v}
    </code>
  );
  const Sec = ({
    id,
    title,
    children,
  }: {
    id: string;
    title: string;
    children: React.ReactNode;
  }) => (
    <div className={activeSection !== id ? "hidden" : "space-y-4"}>
      <div className="border-b border-dark-700 pb-3">
        <h2 className="text-xl font-bold text-white">{title}</h2>
      </div>
      {children}
    </div>
  );
  const Card = ({
    children,
    className = "",
  }: {
    children: React.ReactNode;
    className?: string;
  }) => (
    <div
      className={`bg-dark-800 rounded-lg border border-dark-700 p-4 ${className}`}
    >
      {children}
    </div>
  );
  return (
    <div className="flex gap-6 animate-fade-in">
      <div className="w-44 flex-shrink-0">
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-2 sticky top-6">
          <p className="text-[13px] text-white-600 font-mono mb-2 px-2">
            Contents
          </p>
          {sections.map((s) => (
            <button
              key={s.id}
              onClick={() => setActiveSection(s.id)}
              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors mb-0.5 ${
                activeSection === s.id
                  ? "bg-primary-500/20 text-primary-300 font-medium"
                  : "text-white-300 hover:bg-dark-700 hover:text-white"
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <Sec id="quickstart" title="Quick Start">
          <Card className="space-y-4">
            <p className="text-white-300 text-sm leading-relaxed">
              Axiom Dashboard connects to the{" "}
              <span className="text-white font-semibold">axiom-bridge</span>{" "}
              Python server which communicates with your Axiom framework.
            </p>
            {[
              [
                "1",
                "Start the bridge",
                "python3 tools/axiom-bridge.py — starts the API on port 5000 and watches imports/",
              ],
              [
                "2",
                "Start the frontend",
                "./app/tools/start-dev.sh — opens the dashboard at http://localhost:3000",
              ],
              [
                "3",
                "Verify connection",
                "The ONLINE badge in the header confirms the bridge is reachable.",
              ],
              [
                "4",
                "Select your fleet",
                "Go to Fleet → Refresh. Make sure axiom-select is configured.",
              ],
              [
                "5",
                "Launch a scan",
                "Scans → Launch Scan, pick a module, enter targets, click Launch.",
              ],
            ].map(([n, t, d]) => (
              <div key={n} className="flex gap-4">
                <div className="flex-shrink-0 w-7 h-7 rounded-full bg-primary-500/20 border border-primary-500/30 flex items-center justify-center text-primary-400 font-bold text-xs font-mono">
                  {n}
                </div>
                <div className="pt-0.5">
                  <div className="text-white font-semibold text-sm">{t}</div>
                  <div className="text-white-400 text-sm mt-0.5">{d}</div>
                </div>
              </div>
            ))}
          </Card>
          <Card>
            <h3 className="text-white font-semibold mb-3">
              Environment Variables
            </h3>
            <div className="space-y-2">
              {[
                ["PORT", "5000", "API server port"],
                [
                  "STORE_PATH",
                  "./data/axiom_bridge_store.json",
                  "Target database",
                ],
                ["IMPORTS_PATH", "./imports", "Auto-import watch folder"],
                ["FLEET_CACHE_TTL", "30", "Fleet cache TTL in seconds"],
              ].map(([k, v, d]) => (
                <div
                  key={k}
                  className="flex items-start gap-3 py-1.5 border-b border-dark-700/50 font-mono text-xs"
                >
                  <span className="text-cyan-400 w-36 flex-shrink-0">{k}</span>
                  <span className="text-primary-300 flex-shrink-0">{v}</span>
                  <span className="text-white-500">{d}</span>
                </div>
              ))}
            </div>
          </Card>
        </Sec>
        <Sec id="modules" title="Scan Modules">
          <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-dark-900/60 border-b border-dark-700">
                <tr className="text-[13px] text-white-500 font-mono">
                  <th className="px-4 py-2.5 text-left font-medium">Type</th>
                  <th className="px-4 py-2.5 text-left font-medium">Formats</th>
                  <th className="px-4 py-2.5 text-left font-medium">
                    Description
                  </th>
                </tr>
              </thead>
              <tbody>
                {moduleData.map((m, i) => (
                  <tr
                    key={m.name}
                    className={`border-b border-dark-700/50 ${i % 2 ? "bg-dark-900/20" : ""}`}
                  >
                    <td className="px-4 py-3 font-mono text-cyan-400 font-semibold">
                      {m.name}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-[14px] font-semibold bg-primary-500/15 text-primary-300 border border-primary-500/30 px-2 py-0.5 rounded font-mono">
                        {m.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-white-400 font-mono text-xs">
                      {m.fmt}
                    </td>
                    <td className="px-4 py-3 text-white-300 text-xs">
                      {m.desc}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Card>
            <h3 className="text-white font-semibold mb-2">
              Module availability
            </h3>
            <p className="text-white-300 text-sm">
              The Scan Launcher only shows modules whose binary is installed and
              in PATH on the bridge server. If a module doesn’t appear, install
              the tool in the Axiom image or on the bridge host.
            </p>
          </Card>
        </Sec>
        <Sec id="dashboard" title="Dashboard Guide">
          <div className="space-y-3">
            {[
              [
                "Overview",
                "Shows stat cards, geo map, port chart, and the 5 most recent scan results sorted by date. Click any scan row to jump to its target page.",
              ],
              [
                "Targets",
                "All imported results create target entries. Click a target to see subdomains, ports, vulns, and websites. The default tab matches the scan type.",
              ],
              [
                "Scans → Launch",
                "Select a module, enter targets (one per line), name the scan, and click Launch. Output is auto-generated as module+timestamp.ext.",
              ],
              [
                "Scans → Active/Monitor",
                "Running scans with elapsed time and cancel button. History table sorted newest-first.",
              ],
              [
                "Fleet",
                "Axiom-managed instances. Use checkboxes for bulk power-off or terminate (requires confirmation).",
              ],
              ["Settings", "Configure bridge URL and other preferences."],
            ].map(([t, d]) => (
              <div key={t}>
                <Card>
                  <h3 className="text-white font-semibold text-sm mb-1">{t}</h3>
                  <p className="text-white-300 text-sm">{d}</p>
                </Card>
              </div>
            ))}
          </div>
        </Sec>
        <Sec id="importing" title="Importing Results">
          <Card className="space-y-4">
            <p className="text-white-300 text-sm">
              Drop any scan output file into <C v="imports/" />. The bridge
              detects the scanner type from the filename prefix and imports
              within seconds. No subdirectories needed.
            </p>
            <div>
              <h3 className="text-white font-semibold text-sm mb-3">
                File naming
              </h3>
              <div className="space-y-2 font-mono text-xs">
                {[
                  ["amass+02-25_17-00.txt", "amass parser, txt format"],
                  ["nuclei+02-25_17-00.jsonl", "nuclei parser, jsonl format"],
                  ["nmap+02-25_17-00.xml", "nmap parser, xml format"],
                  [
                    "whois+02-25_17-00.txt",
                    "whois parser, country code → geo map",
                  ],
                ].map(([f, d]) => (
                  <div key={f} className="flex items-center gap-3">
                    <span className="text-cyan-400 w-52 flex-shrink-0">
                      {f}
                    </span>
                    <span className="text-white-500">→</span>
                    <span className="text-white-300">{d}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h3 className="text-white font-semibold text-sm mb-2">
                Import lifecycle
              </h3>
              <ol className="space-y-1 text-sm text-white-300">
                <li>1. Bridge classifies file by name prefix</li>
                <li>
                  2. Content parsed into target / subdomain / vuln records
                </li>
                <li>3. Records merge with existing targets (no duplicates)</li>
                <li>
                  4. File moved to <C v="imports/processed/" />
                </li>
                <li>5. Dashboard auto-refreshes every 30 seconds</li>
              </ol>
            </div>
          </Card>
        </Sec>
        <Sec id="fleet" title="Fleet Management">
          <div className="space-y-3">
            <Card>
              <h3 className="text-white font-semibold mb-2">
                Instance selection
              </h3>
              <p className="text-white-300 text-sm">
                Fleet shows Axiom-managed instances from{" "}
                <C v="~/.axiom/selected.conf" />. Use the filter dropdown for
                all vs managed. Row checkboxes enable bulk{" "}
                <span className="text-white font-medium">Power Off</span> /
                <span className="text-danger-400 font-medium"> Terminate</span>{" "}
                actions.
              </p>
            </Card>
            <Card>
              <h3 className="text-white font-semibold mb-2">Fleet cache</h3>
              <p className="text-white-300 text-sm">
                Fleet data is cached for{" "}
                <span className="text-white font-medium">30 s</span> (env{" "}
                <C v="FLEET_CACHE_TTL" />) to avoid hammering the cloud API.
                Click <span className="text-white font-medium">↺ Refresh</span>{" "}
                to force a fresh query.
              </p>
            </Card>
            <Card>
              <h3 className="text-white font-semibold mb-2">Safety</h3>
              <ul className="space-y-1.5 text-sm text-white-300">
                <li>
                  • All{" "}
                  <span className="text-danger-400 font-medium">Terminate</span>{" "}
                  actions require a confirmation dialog
                </li>
                <li>• Bulk terminate shows instance count before confirming</li>
                <li>• Power off is reversible; terminate is permanent</li>
                <li>• Only Axiom-managed instances shown by default</li>
              </ul>
            </Card>
          </div>
        </Sec>
        <Sec id="notifications" title="Notifications">
          <div className="space-y-3">
            <Card>
              <h3 className="text-white font-semibold mb-2">
                In-app notifications
              </h3>
              <p className="text-white-300 text-sm mb-3">
                The bell icon shows unread count. Click it to open the panel.
                Toast notifications auto-dismiss after 5 s.
              </p>
              <ul className="space-y-1.5 text-sm text-white-300">
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 flex-shrink-0" />{" "}
                  Scan started
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-success-400 flex-shrink-0" />{" "}
                  Scan completed
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-danger-400 flex-shrink-0" />{" "}
                  Scan failed
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-warn-400 flex-shrink-0" />{" "}
                  Fleet action (power off / terminate)
                </li>
              </ul>
            </Card>
            <Card>
              <h3 className="text-white font-semibold mb-2">
                Browser notifications
              </h3>
              <p className="text-white-300 text-sm">
                When you grant browser notification permission, native OS
                notifications are sent when scans complete or fleet actions
                finish — useful when the dashboard is in a background tab.
                Permission is requested automatically the first time a
                notification fires.
              </p>
            </Card>
          </div>
        </Sec>
      </div>
    </div>
  );
};

// ───────────── Main App ─────────────

const App = () => {
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const navigate = useNavigate();
  const location = useLocation();

  // ── Notification state ──────────────────────────────
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [toastQueue, setToastQueue] = useState<AppNotification[]>([]);
  const [showNotifPanel, setShowNotifPanel] = useState(false);
  const prevScanStatuses = useRef<Record<string, string>>({});

  const addNotification = useCallback(
    (type: string, title: string, message: string) => {
      const notif: AppNotification = {
        id: `${Date.now()}-${Math.random()}`,
        type,
        title,
        message,
        time: new Date(),
        read: false,
      };
      setNotifications((prev) => [notif, ...prev].slice(0, 50));
      setToastQueue((prev) => [...prev, notif]);
      setTimeout(() => {
        setToastQueue((prev) => prev.filter((n) => n.id !== notif.id));
      }, 5000);
      if ("Notification" in window) {
        if (Notification.permission === "default") {
          Notification.requestPermission();
        } else if (Notification.permission === "granted") {
          new Notification(title, { body: message });
        }
      }
    },
    [],
  );

  const unreadCount = notifications.filter((n) => !n.read).length;
  const markAllRead = () =>
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));

  // ── Load targets ───────────────────────────────────
  const loadTargets = async () => {
    setLoading(true);
    try {
      // Trigger an import scan first so any newly dropped files are processed
      // before we fetch. Fire-and-forget on initial load; awaited on manual refresh.
      fetch("http://localhost:5000/api/imports/scan").catch(() => {});
      const data = await fetchTargets();
      setTargets(data);
      setLastUpdated(new Date());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTargets();
    const interval = setInterval(() => {
      loadTargets();
    }, 300_000); // 5 minutes
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const path = location.pathname;
    if (path.startsWith("/targets/")) {
      const id = path.split("/")[2];
      const found = targets.find((t) => t.id === id);
      if (found) setSelectedTarget(found);
    } else {
      setSelectedTarget(null);
    }
  }, [location, targets]);

  // ── Poll scan statuses for notifications ────────────────
  useEffect(() => {
    let initialised = false;

    const pollScans = async () => {
      try {
        const resp = await fetch("http://localhost:5000/api/axiom/scans");
        if (!resp.ok) return;
        const scans: any[] = await resp.json();

        // On the very first poll, seed prevScanStatuses without firing any
        // notifications — avoids false "started" toasts for scans that were
        // already running when the dashboard opened.
        if (!initialised) {
          scans.forEach((scan) => {
            prevScanStatuses.current[scan.id] = scan.status;
          });
          initialised = true;
          return;
        }

        scans.forEach((scan) => {
          const prev = prevScanStatuses.current[scan.id];
          const curr = scan.status;
          const label = scan.name || scan.id;

          if (!prev && curr === "running") {
            // Brand-new scan appeared mid-session
            addNotification(
              "scan_started",
              "🚀 Scan Started",
              `${label} · ${scan.module || ""}`,
            );
          } else if (prev === "running" && curr === "completed") {
            const resultCount: number = scan.resultCount ?? scan.results ?? -1;
            if (resultCount === 0) {
              addNotification(
                "scan_empty",
                "⚠️ Scan Finished — 0 Results",
                `${label} completed but returned no output. The input format may be incorrect for this module.`,
              );
            } else {
              addNotification(
                "scan_completed",
                "✅ Scan Completed",
                `${label} finished${resultCount > 0 ? ` · ${resultCount} results` : ""}`,
              );
            }
          } else if (
            prev === "running" &&
            (curr === "failed" || curr === "error")
          ) {
            addNotification(
              "scan_failed",
              "❌ Scan Failed",
              `${label} failed${scan.error ? ` — ${scan.error}` : ""}`,
            );
          }

          prevScanStatuses.current[scan.id] = curr;
        });
      } catch {}
    };

    // Run immediately so the panel is populated quickly, then every 15 s
    pollScans();
    const interval = setInterval(pollScans, 15_000);
    return () => clearInterval(interval);
  }, [addNotification]);

  const notifDotColor = (type: string) =>
    type === "scan_completed"
      ? "bg-success-400"
      : type === "scan_failed"
        ? "bg-danger-400"
        : type === "scan_empty"
          ? "bg-yellow-400"
          : type === "scan_started"
            ? "bg-cyan-400"
            : type.startsWith("fleet_")
              ? "bg-warn-400"
              : "bg-primary-400";

  return (
    <div className="min-h-screen bg-dark-900 text-white-100 font-sans selection:bg-primary-500/30">
      <Sidebar />
      <Header
        unreadCount={unreadCount}
        onBellClick={() => setShowNotifPanel((v) => !v)}
      />
      <main className="ml-56 pt-12">
        <div className="p-6 max-w-none">
          <Routes>
            <Route
              path="/"
              element={
                <DashboardHomeExternal
                  targets={targets}
                  loading={loading}
                  onRefresh={loadTargets}
                />
              }
            />
            <Route
              path="/scans"
              element={<ScansPage onTargetsRefresh={loadTargets} />}
            />
            <Route
              path="/fleet"
              element={<FleetControlPage onNotify={addNotification} />}
            />
            <Route path="/settings" element={<Settings />} />
            <Route path="/docs" element={<DocsPage />} />
            <Route path="/vulns" element={<VulnsPage targets={targets} />} />
            <Route
              path="/targets"
              element={
                <TargetsList
                  targets={targets}
                  onSelectTarget={(t) => {
                    navigate(`/targets/${t.id}`);
                  }}
                  onRefresh={loadTargets}
                  loading={loading}
                  lastUpdated={lastUpdated}
                />
              }
            />
            <Route
              path="/targets/:id"
              element={
                selectedTarget ? (
                  <TargetDetail target={selectedTarget} />
                ) : (
                  <div className="text-center mt-20 text-white-500">
                    Loading Target...
                  </div>
                )
              }
            />
            <Route
              path="*"
              element={
                <div className="text-center mt-20 text-white-500">
                  Module Under Construction
                </div>
              }
            />
          </Routes>
        </div>
      </main>

      {/* Notification Toasts */}
      <div className="fixed top-16 right-4 z-[200] space-y-2 pointer-events-none">
        {toastQueue.map((n) => (
          <div
            key={n.id}
            className="bg-dark-800 border border-dark-700 rounded-lg p-3 flex items-start gap-3 pointer-events-auto min-w-[260px] max-w-[340px] animate-fade-in"
          >
            <div
              className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${notifDotColor(n.type)}`}
            />
            <div className="flex-1 min-w-0">
              <div className="text-white text-sm font-semibold">{n.title}</div>
              <div className="text-white-400 text-xs mt-0.5">{n.message}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Notification Panel */}
      {showNotifPanel && (
        <div className="fixed top-12 right-0 z-[150] w-72 bg-dark-800 border border-dark-700 rounded-b-lg shadow-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
            <span className="text-sm font-semibold text-white">
              Notifications
            </span>
            <div className="flex items-center gap-3">
              <button
                onClick={markAllRead}
                className="text-[13px] text-white-400 hover:text-white transition-colors"
              >
                Mark all read
              </button>
              <button
                onClick={() => setShowNotifPanel(false)}
                className="text-white-400 hover:text-white transition-colors"
              >
                <X size={14} />
              </button>
            </div>
          </div>
          <div className="max-h-[420px] overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="text-center py-10 text-white-500 text-sm font-mono">
                No notifications yet
              </div>
            ) : (
              notifications.slice(0, 20).map((n) => (
                <div
                  key={n.id}
                  className={`px-4 py-3 border-b border-dark-700/50 hover:bg-dark-700/30 transition-colors ${
                    n.read ? "opacity-50" : ""
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <div
                      className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${n.read ? "bg-dark-600" : notifDotColor(n.type)}`}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-white font-medium">
                        {n.title}
                      </div>
                      <div className="text-xs text-white-400 mt-0.5">
                        {n.message}
                      </div>
                      <div className="text-[13px] text-white-600 mt-1 font-mono">
                        {n.time.toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// Use MemoryRouter to avoid Location.assign access errors in sandboxed/blob environments
// DashboardHomeExternal is a wrapper to pass props from App
const DashboardHomeExternal = ({
  targets,
  loading,
  onRefresh,
}: {
  targets: Target[];
  loading: boolean;
  onRefresh: () => void;
}) => {
  const navigate = useNavigate();
  const [fleet, setFleet] = useState<FleetInstance[]>([]);
  const [runningScansCount, setRunningScansCount] = useState(0);

  useEffect(() => {
    const loadFleetData = async () => {
      try {
        const data = await fetchFleet(false); // Use cache for dashboard
        setFleet(data);
      } catch (error) {
        console.warn("Failed to load fleet:", error);
      }
    };
    loadFleetData();

    // Refresh fleet data every 60 seconds (will use cache if within TTL)
    const interval = setInterval(loadFleetData, 60000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const loadScansCount = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/axiom/scans");
        if (res.ok) {
          const data: any[] = await res.json();
          setRunningScansCount(
            Array.isArray(data)
              ? data.filter((s) => s.status === "running").length
              : 0,
          );
        }
      } catch {
        // bridge offline — leave count as-is
      }
    };
    loadScansCount();
    const interval = setInterval(loadScansCount, 30_000);
    return () => clearInterval(interval);
  }, []);

  // Enhanced dashboard metrics
  const metrics = getDashboardMetrics(targets, fleet);

  // Fleet region data for graph
  const fleetRegionData = Object.entries(metrics.fleetRegions).map(
    ([region, count]) => ({ region, count }),
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-white-300 font-mono">
          Overview
        </h1>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="text-xs text-white-500 hover:text-white-300 font-mono transition-colors disabled:opacity-50"
        >
          {loading ? "Syncing..." : "↻ Refresh"}
        </button>
      </div>

      {/* Stat Cards Row 1 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Scans"
          value={metrics.totalTargets}
          icon={TargetIcon}
          accentClass="stat-card-target"
          iconBg="bg-primary-500/10"
          iconColor="text-primary-400"
          onClick={() => navigate("/targets")}
        />
        <StatCard
          title="Subdomains"
          value={metrics.totalSubdomains}
          icon={Globe}
          accentClass="stat-card-sub"
          iconBg="bg-cyan-500/10"
          iconColor="text-cyan-400"
          onClick={() => navigate("/targets")}
        />
        <StatCard
          title="Open Ports"
          value={metrics.totalPorts}
          icon={Server}
          accentClass="stat-card-port"
          iconBg="bg-blue-500/10"
          iconColor="text-blue-400"
          onClick={() => navigate("/targets")}
        />
        <StatCard
          title="Vulnerabilities"
          value={metrics.totalVulns}
          icon={ShieldAlert}
          accentClass="stat-card-vuln"
          iconBg="bg-danger-500/10"
          iconColor="text-danger-400"
          onClick={() => navigate("/targets")}
        />
      </div>

      {/* Stat Cards Row 2 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Critical / High"
          value={metrics.highCriticalVulns}
          icon={ShieldAlert}
          accentClass="stat-card-critical"
          iconBg="bg-orange-500/10"
          iconColor="text-orange-400"
          onClick={() => navigate("/vulns?sev=CRITICAL")}
        />
        <StatCard
          title="Active Scans"
          value={runningScansCount}
          icon={Activity}
          accentClass="stat-card-scan"
          iconBg="bg-success-500/10"
          iconColor="text-success-400"
          onClick={() => navigate("/scans")}
        />
        <StatCard
          title="Fleet Nodes"
          value={`${metrics.fleetActive} / ${metrics.fleetTotal}`}
          icon={Server}
          accentClass="stat-card-fleet"
          iconBg="bg-primary-400/10"
          iconColor="text-primary-300"
          onClick={() => navigate("/fleet")}
        />
        <div
          onClick={() => navigate("/targets")}
          className="rounded-lg p-4 flex flex-col justify-center bg-dark-800 border border-dark-700 border-l-2 stat-card-scan card-hover cursor-pointer"
        >
          <div className="text-xs text-white-400 font-mono mb-1">
            Scan Success
          </div>
          <div className="text-xl font-bold text-white tabular-nums mb-2">
            {targets.length > 0
              ? Math.round(
                  (targets.filter((t) => t.status === "COMPLETED").length /
                    targets.length) *
                    100,
                )
              : 0}
            %
          </div>
          <div className="w-full bg-dark-700 rounded h-1">
            <div
              className="bg-success-500 h-1 rounded transition-all"
              style={{
                width: `${targets.length > 0 ? (targets.filter((t) => t.status === "COMPLETED").length / targets.length) * 100 : 0}%`,
              }}
            />
          </div>
        </div>
      </div>

      {/* Middle row: Ports chart + Assets + Fleet Health + Fleet Regions */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Most Common Ports */}
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-4 card-hover">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-white-300">
              Top Open Ports
            </h3>
            <button
              onClick={() => navigate("/targets")}
              className="text-xs text-white-500 hover:text-white-300 font-mono transition-colors"
            >
              View all →
            </button>
          </div>
          {(() => {
            const commonPorts = getCommonPorts(targets);
            const top5 = commonPorts.slice(0, 5);
            const maxCount = top5[0]?.count || 1;
            return commonPorts.length === 0 ? (
              <p className="text-white-500 text-xs text-[13px] text-center py-8 font-mono">
                No port data yet
              </p>
            ) : (
              <div className="flex items-center gap-3">
                {/* Pie chart — left */}
                <div className="flex pt-5 pl-5">
                  <ResponsiveContainer width={160} height={160}>
                    <PieChart>
                      <Pie
                        data={commonPorts}
                        dataKey="count"
                        nameKey="port"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        innerRadius={40}
                        paddingAngle={2}
                        onClick={() => navigate("/targets")}
                        style={{ cursor: "pointer" }}
                      >
                        {commonPorts.map((_, index) => (
                          <Cell
                            key={`cell-port-${index}`}
                            fill={pieColors[index % pieColors.length]}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#0f172a",
                          border: "1px solid #1e293b",
                          borderRadius: "8px",
                          padding: "6px 10px",
                        }}
                        itemStyle={{ color: "#e2e8f0", fontSize: "13px" }}
                        labelStyle={{ color: "#64748b", fontSize: "13px" }}
                        formatter={(value, name) => [
                          `${value} hits`,
                          `Port ${name}`,
                        ]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                {/* Top-5 legend — right */}
                <div className="flex-1 space-y-1.5 min-w-0 text-[13px] pl-[25%]">
                  {top5.map((entry, index) => (
                    <div key={entry.port} className="flex items-center gap-2">
                      <span
                        className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{
                          backgroundColor: pieColors[index % pieColors.length],
                        }}
                      />
                      <span className="font-mono text-[13px] text-white-200 w-10 flex-shrink-0">
                        {entry.port}
                      </span>
                      <div className="flex-1 bg-dark-700 rounded-full h-1 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${(entry.count / maxCount) * 100}%`,
                            backgroundColor:
                              pieColors[index % pieColors.length],
                          }}
                        />
                      </div>
                      <span className="font-mono text-[13px] text-white-500 flex-shrink-0">
                        {entry.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>

        {/* Top Discovered Assets */}
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-4 card-hover">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[13px] font-semibold text-white-300">
              Top Assets
            </h3>
            <button
              onClick={() => navigate("/targets")}
              className="text-xs text-white-500 hover:text-white-300 font-mono transition-colors"
            >
              View all →
            </button>
          </div>
          <ul className="max-h-[220px] overflow-y-auto scrollbar-purple">
            {getTopAssets(targets).length === 0 ? (
              <li className="text-white-500 text-[13px] text-center py-8 font-mono">
                No data yet
              </li>
            ) : (
              getTopAssets(targets).map((asset, idx) => (
                <li
                  key={asset.name}
                  onClick={() => {
                    const t = targets.find((t) => t.domain === asset.name);
                    if (t) navigate(`/targets/${t.id}`);
                    else navigate("/targets");
                  }}
                  className="flex items-center justify-between px-2 py-1.5 rounded-lg hover:bg-dark-700/50 transition-colors group cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[13px] font-bold text-white-500 font-mono w-4">
                      {idx + 1}
                    </span>
                    <span className="font-mono text-[14px] text-white-200 group-hover:text-white transition-colors truncate max-w-[250px]">
                      {asset.name}
                    </span>
                  </div>
                  <span className="text-[13px] font-semibold text-primary-400 font-mono bg-primary-500/10 px-2 rounded">
                    {asset.count}
                  </span>
                </li>
              ))
            )}
          </ul>
        </div>

        {/* Fleet Health */}
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-4 card-hover">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-white-300">
              Fleet Health
            </h3>
            <button
              onClick={() => navigate("/fleet")}
              className="text-xs text-white-500 hover:text-white-300 font-mono transition-colors"
            >
              Manage →
            </button>
          </div>
          <div className="space-y-2.5">
            {[
              {
                label: "Running",
                count: fleet.filter((f) => f.status === "running").length,
                color: "text-success-400",
                dot: "bg-success-400",
              },
              {
                label: "Stopped",
                count: fleet.filter((f) => f.status === "stopped").length,
                color: "text-warn-400",
                dot: "bg-warn-400",
              },
              {
                label: "Terminated",
                count: fleet.filter((f) => f.status === "terminated").length,
                color: "text-white-400",
                dot: "bg-dark-500",
              },
            ].map((row) => (
              <div
                key={row.label}
                onClick={() => navigate("/fleet")}
                className="flex items-center justify-between bg-dark-900/50 rounded-lg px-3 py-2.5 cursor-pointer hover:bg-dark-700/60 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${row.dot}`} />
                  <span className="text-xs text-white-300">{row.label}</span>
                </div>
                <span className={`text-sm font-bold font-mono ${row.color}`}>
                  {row.count}
                </span>
              </div>
            ))}
            <div className="pt-1">
              <div className="flex justify-between text-[13px] text-white-500 font-mono mb-1">
                <span>Capacity</span>
                <span>
                  {metrics.fleetUtilization > 0
                    ? (metrics.fleetUtilization * 100).toFixed(0)
                    : 0}
                  %
                </span>
              </div>
              <div className="w-full bg-dark-700 rounded h-1">
                <div
                  className="bg-primary-500 h-1 rounded"
                  style={{
                    width: `${(metrics.fleetUtilization * 100).toFixed(0)}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Fleet Regions — compact pie + stacked legend */}
        <div className="bg-dark-800 rounded-lg border border-dark-700 p-4 card-hover">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-white-300">
              Fleet Regions
            </h3>
            <button
              onClick={() => navigate("/fleet")}
              className="text-xs text-white-500 hover:text-white-300 font-mono transition-colors"
            >
              Manage →
            </button>
          </div>
          {fleetRegionData.length === 0 ? (
            <div className="text-white-500 text-xs text-center py-8 font-mono">
              No fleet data
            </div>
          ) : (
            <div className="flex items-center gap-3">
              {/* Pie — taller and wider */}
              <div className="flex pt-5 pl-5">
                <ResponsiveContainer width={160} height={160}>
                  <PieChart>
                    <Pie
                      data={fleetRegionData}
                      dataKey="count"
                      nameKey="region"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      innerRadius={40}
                      paddingAngle={2}
                      onClick={() => navigate("/fleet")}
                      style={{ cursor: "pointer" }}
                    >
                      {fleetRegionData.map((entry, index) => (
                        <Cell
                          key={`cell-region-${index}`}
                          fill={pieColors[index % pieColors.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0f172a",
                        border: "1px solid #1e293b",
                        borderRadius: "8px",
                        padding: "6px 10px",
                      }}
                      itemStyle={{ color: "#e2e8f0", fontSize: "11px" }}
                      formatter={(value, name) => [`${value} nodes`, name]}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Legend alongside */}
              <div className="flex-1 min-w-0 space-y-1.5 pl-[25%] text-[13px]">
                {fleetRegionData.slice(0, 7).map((entry, index) => (
                  <div
                    key={entry.region}
                    onClick={() => navigate("/fleet")}
                    className="flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity rounded px-1 py-0.5"
                  >
                    <span
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{
                        backgroundColor: pieColors[index % pieColors.length],
                      }}
                    />
                    <span className="text-[13px] text-white-300 font-mono truncate flex-1">
                      {entry.region}
                    </span>
                    <span className="text-[13px] font-bold text-white font-mono">
                      {entry.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Geo Map */}
      <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
        <div className="px-4 py-3 border-b border-dark-700">
          <h3 className="text-xs font-semibold text-white-300">
            Global Recon Map
          </h3>
        </div>
        <div className="p-4">
          <GeoMap targets={targets} />
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
        <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
          <h3 className="text-xs font-semibold text-white-300">Recent Scans</h3>
          <button
            className="text-xs text-white-500 hover:text-white-300 font-mono transition-colors disabled:opacity-40"
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? "Syncing..." : "↻ Refresh"}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="border-b border-dark-700">
              <tr className="text-[13px] text-white-500 font-mono">
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Found</th>
                <th className="px-4 py-2.5 font-medium">Vulns</th>
                <th className="px-4 py-2.5"></th>
              </tr>
            </thead>
            <tbody>
              {targets.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="px-5 py-12 text-center text-white-500 text-sm font-mono"
                  >
                    No scan data — run your first scan
                  </td>
                </tr>
              ) : (
                [...targets]
                  .sort(
                    (a, b) =>
                      new Date(b.lastScanDate || 0).getTime() -
                      new Date(a.lastScanDate || 0).getTime(),
                  )
                  .slice(0, 5)
                  .map((target) => (
                    <tr
                      key={target.id}
                      className="border-b border-dark-700/50 hover:bg-dark-700/20 transition-colors cursor-pointer"
                      onClick={() => navigate(`/targets/${target.id}`)}
                    >
                      <td className="px-4 py-3">
                        <div className="text-sm text-white font-mono">
                          {target.domain}
                        </div>
                        <div className="text-xs text-white-500 font-mono mt-0.5">
                          {target.programName}
                        </div>
                      </td>
                      <td className="px-5 py-3.5">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[14px] font-semibold font-mono ${
                            target.status === "RUNNING"
                              ? "badge-running"
                              : target.status === "COMPLETED"
                                ? "badge-completed"
                                : target.status === "FAILED"
                                  ? "badge-failed"
                                  : "badge-pending"
                          }`}
                        >
                          {target.status === "RUNNING" && (
                            <span className="w-1.5 h-1.5 rounded-full bg-warn-400 animate-pulse" />
                          )}
                          {target.status}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className="text-sm font-mono text-white-200">
                          {getScanMetrics(target).count}
                        </span>
                        <span className="text-[13px] text-white-500 ml-1">
                          {getScanMetrics(target).label}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        {target.vulnerabilities?.length > 0 ? (
                          <span className="text-sm font-bold font-mono text-danger-400">
                            {target.vulnerabilities.length}
                          </span>
                        ) : (
                          <span className="text-sm text-white-600 font-mono">
                            —
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        <ChevronRight className="w-4 h-4 text-white-600" />
                      </td>
                    </tr>
                  ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const AppWrapper = () => (
  <Router>
    <App />
  </Router>
);

export default AppWrapper;
