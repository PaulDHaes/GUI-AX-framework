import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
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
  User,
  ChevronRight,
  ChevronDown,
  LayoutDashboard,
  Settings as SettingsIcon,
  Target as TargetIcon,
  BookOpen,
  X,
  Download,
  Copy,
  ScanLine,
  Database,
  Flag,
  Filter,
  FolderKanban,
  Layers,
  LogOut,
  Shield,
  Users,
  Sun,
  Moon,
  Cpu,
} from "lucide-react";
import ScanLauncher from "./components/ScanLauncher";
import ActiveScans from "./components/ActiveScans";
import ScanOutput from "./components/ScanOutput";
import FleetControl from "./components/FleetControl";
import TopologyGraph from "./components/TopologyGraph";
import Settings from "./components/Settings";
import GeoMap from "./components/GeoMap";
import BinocularsSkullLogo from "./components/ui/BinocularsSkullLogo";
import WorkflowBuilder from "./components/WorkflowBuilder";
import LoginPage from "./components/LoginPage";
import UserProfile from "./components/UserProfile";
import AdminPanel from "./components/AdminPanel";
import FindingsTriage from "./components/FindingsTriage";
import WordlistManager from "./components/WordlistManager";
import QuickScanPage from "./components/QuickScan";
import ProjectsPage from "./components/ProjectsPage";
import InventoryMonitor from "./components/InventoryMonitor";
// shadcn/ui primitives
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { TooltipProvider } from "@/components/ui/tooltip";
import { cn, ansiToHtml } from "@/lib/utils";
import { useActiveProject } from "@/lib/useActiveProject";
import { BRIDGE_BASE } from "@/lib/bridge";
// Types
import type { Target, FleetInstance, ProjectTeam, AxProject } from "./types";
// Severity enum (if not imported from types)
import { Severity } from "./types";
import { getTheme, toggleTheme, type Theme } from "./services/prefs";

// ── Team slug helper (must match ScanLauncher prefix logic) ─────────────────
function toTeamSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}



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
      className={`relative rounded-xl bg-card border border-border tile-hover ${onClick ? "cursor-pointer" : ""} ${accentClass}`}
    >
      <div className="tile-shine" />
      <div className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div
            className={`h-9 w-9 rounded-lg flex items-center justify-center ${iconBg}`}
          >
            {Icon && <Icon className={`w-[18px] h-[18px] ${iconColor}`} />}
          </div>
          {trend && (
            <span className="text-[10px] font-mono text-success-400 bg-success-500/10 px-1.5 py-0.5 rounded border border-success-500/15">
              {trend}
            </span>
          )}
        </div>
        <div className="text-2xl font-bold text-card-foreground tabular-nums tracking-tight leading-none mb-1">
          {value}
        </div>
        <div className="text-[11px] text-muted-foreground font-mono uppercase tracking-wider">
          {title}
        </div>
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
// Debounce hook — avoids re-filtering on every keystroke in large vuln lists
function useDebounce<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

// Rekono-inspired risk score (0–100) based on vulnerability severity weights
function computeRiskScore(target: any): {
  score: number;
  level: string;
  color: string;
} {
  const weights: Record<string, number> = {
    CRITICAL: 10,
    HIGH: 5,
    MEDIUM: 2,
    LOW: 0.5,
    INFO: 0,
  };
  const fpIds = new Set(target.falsePositiveVulnIds || []);
  const vulns: any[] = target.vulnerabilities || [];
  let raw = vulns
    .filter((v: any) => !fpIds.has(v.id))
    .reduce(
      (acc: number, v: any) =>
        acc + (weights[(v.severity || "").toUpperCase()] ?? 0),
      0,
    );
  const ports = (target.subdomains || []).reduce(
    (n: number, s: any) => n + (s.ports?.length || 0),
    0,
  );
  raw += ports * 0.1;
  const score = Math.min(100, Math.round(raw * 10) / 10);
  if (score >= 75)
    return {
      score,
      level: "CRITICAL",
      color: "text-danger-400 bg-danger-500/10 border-danger-500/20",
    };
  if (score >= 40)
    return {
      score,
      level: "HIGH",
      color: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    };
  if (score >= 15)
    return {
      score,
      level: "MEDIUM",
      color: "text-warn-400 bg-warn-500/10 border-warn-500/20",
    };
  if (score > 0)
    return {
      score,
      level: "LOW",
      color: "text-success-400 bg-success-500/10 border-success-500/20",
    };
  return {
    score: 0,
    level: "NONE",
    color: "text-muted-foreground/80 bg-secondary border-border",
  };
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
  const [scanTypeFilter, setScanTypeFilter] = useState("");
  const navigate = useNavigate();
  const [reimporting, setReimporting] = useState(false);

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

  // Format "X ago" label
  const updatedLabel = (() => {
    if (!lastUpdated) return null;
    const secs = Math.floor((Date.now() - lastUpdated.getTime()) / 1000);
    if (secs < 60) return "just now";
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    return `${Math.floor(secs / 3600)}h ago`;
  })();

  // Extract scanner type(s) from source filenames for a target.
  // Stop chars: + . _ -  so "httpx+09-14_..." → "httpx", "dnsx-out-full.txt" → "dnsx",
  // "nuclei_targets.txt" → "nuclei", "gowitness_covert" → "gowitness".
  const getScannerTypes = (target: any): string[] => {
    const types = new Set<string>();
    for (const src of (target.sources || [])) {
      const s = String(src);
      // gw-* source names are gowitness scan aliases
      if (/^gw-/i.test(s)) { types.add("gowitness"); continue; }
      const m = s.match(/^([a-z][a-z0-9]*?)[+._-]/i);
      if (m) types.add(m[1].toLowerCase());
    }
    if (types.size === 0) {
      const pn = (target.programName || "").toLowerCase();
      if (pn.includes("gowitness")) types.add("gowitness");
    }
    return [...types];
  };

  // Unique scanner types present in current targets for the dropdown
  const availableScanTypes = Array.from(
    new Set(targets.flatMap((t) => getScannerTypes(t)))
  ).sort();

  // Filter targets based on search query and scan type, then sort newest first
  const filteredTargets = targets
    .filter((target) => {
      const query = searchQuery.toLowerCase().trim();
      const textOk = !query ||
        target.domain?.toLowerCase().includes(query) ||
        target.programName?.toLowerCase().includes(query) ||
        target.id?.toLowerCase().includes(query);
      const typeOk = !scanTypeFilter ||
        getScannerTypes(target).includes(scanTypeFilter);
      return textOk && typeOk;
    })
    .sort(
      (a, b) =>
        new Date(b.lastScanDate || 0).getTime() -
        new Date(a.lastScanDate || 0).getTime(),
    );
  if (scanTypeFilter) {
    console.log("[filter] scanTypeFilter=" + scanTypeFilter + " => " + filteredTargets.length + "/" + targets.length + " targets", filteredTargets.map(t => ({domain: t.domain, types: getScannerTypes(t)})));
  }

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Top bar: title + search + actions */}
      <div className="flex justify-between items-center gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-sm font-semibold text-foreground/80 font-mono flex-shrink-0">
            Targets
          </span>
          <span className="text-xs text-muted-foreground/80 font-mono flex-shrink-0">
            {filteredTargets.length}{targets.length !== filteredTargets.length ? ` / ${targets.length}` : ""}
          </span>
          {updatedLabel && (
            <span className="text-xs text-muted-foreground/80 font-mono flex-shrink-0">
              · {updatedLabel}
            </span>
          )}
        </div>
        <div className="flex gap-2 items-center flex-shrink-0">
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={loading}
              title="Refresh targets"
              className="bg-secondary hover:bg-accent disabled:opacity-40 border border-border/60 text-foreground/80 hover:text-foreground px-3 py-2 rounded-lg text-sm transition-colors font-mono"
            >
              {loading ? "⟳ …" : "↺ Refresh"}
            </button>
          )}
          <div className="relative">
            <input
              type="text"
              placeholder="Search targets..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-card border border-border/60 rounded-lg pl-3 pr-8 py-2 text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary-500/60 focus:ring-1 focus:ring-primary-500/20 w-52 font-mono transition-all"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground text-xs"
              >
                ✕
              </button>
            )}
          </div>
          <button
            onClick={() => navigate("/scans")}
            className="bg-primary-600 hover:bg-primary-500 text-foreground px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex-shrink-0"
          >
            + New Scan
          </button>
        </div>
      </div>

      {/* Scan-type filter pills */}
      {availableScanTypes.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-[11px] text-muted-foreground/60 font-mono mr-1">Filter:</span>
          <button
            onClick={() => setScanTypeFilter("")}
            className={`px-2.5 py-1 rounded-full text-[11px] font-mono border transition-all ${
              !scanTypeFilter
                ? "bg-primary-500/20 border-primary-500/50 text-primary-300 font-semibold"
                : "bg-secondary/60 border-border/50 text-muted-foreground hover:bg-secondary hover:text-foreground"
            }`}
          >
            all
          </button>
          {availableScanTypes.map((t) => (
            <button
              key={t}
              onClick={() => setScanTypeFilter(scanTypeFilter === t ? "" : t)}
              className={`px-2.5 py-1 rounded-full text-[11px] font-mono border transition-all ${
                scanTypeFilter === t
                  ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-semibold"
                  : "bg-secondary/60 border-border/50 text-muted-foreground hover:bg-secondary hover:text-foreground"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      )}

      {/* Active filter banner */}
      {(scanTypeFilter || searchQuery) && (
        <div className="flex items-center gap-2 px-3 py-2 bg-cyan-500/5 border border-cyan-500/20 rounded-lg text-xs font-mono text-cyan-400">
          <span>Showing</span>
          <span className="font-bold text-cyan-300">{filteredTargets.length}</span>
          <span>of {targets.length} targets</span>
          {scanTypeFilter && (
            <span className="flex items-center gap-1 ml-1 bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 rounded-full">
              scanner: <span className="font-bold">{scanTypeFilter}</span>
              <button onClick={() => setScanTypeFilter("")} className="ml-1 opacity-60 hover:opacity-100">✕</button>
            </span>
          )}
          {searchQuery && (
            <span className="flex items-center gap-1 ml-1 bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 rounded-full">
              search: <span className="font-bold">"{searchQuery}"</span>
              <button onClick={() => setSearchQuery("")} className="ml-1 opacity-60 hover:opacity-100">✕</button>
            </span>
          )}
          <button
            onClick={() => { setScanTypeFilter(""); setSearchQuery(""); }}
            className="ml-auto text-muted-foreground hover:text-foreground"
          >
            Clear all
          </button>
        </div>
      )}

      {filteredTargets.length === 0 ? (
        (searchQuery || scanTypeFilter) ? (
          <div className="text-center py-24 text-muted-foreground">
            <Globe className="w-10 h-10 mx-auto mb-3 opacity-20" />
            <p className="text-sm font-mono">
              No targets match{searchQuery ? ` "${searchQuery}"` : ""}{scanTypeFilter ? ` [${scanTypeFilter}]` : ""}
            </p>
            <button
              onClick={() => { setSearchQuery(""); setScanTypeFilter(""); }}
              className="mt-3 text-primary-400 hover:text-primary-300 text-xs font-mono"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="text-center py-24 text-muted-foreground">
            <Globe className="w-10 h-10 mx-auto mb-3 opacity-20" />
            <p className="text-sm font-mono mb-1">No targets imported yet</p>
            <p className="text-xs text-muted-foreground/80 font-mono mb-4">
              Drop scan output files into{" "}
              <code className="text-cyan-500">imports/</code> or re-import
              previously processed files.
            </p>
            <div className="flex items-center justify-center gap-3">
              <button
                onClick={() => navigate("/scans")}
                className="bg-primary-600 hover:bg-primary-500 text-foreground px-4 py-2 rounded-lg text-xs font-semibold transition-colors"
              >
                Launch a Scan
              </button>
              <button
                onClick={handleReimport}
                disabled={reimporting}
                className="bg-secondary hover:bg-accent disabled:opacity-40 border border-border/60 text-foreground/80 hover:text-foreground px-4 py-2 rounded-lg text-xs font-mono transition-colors"
              >
                {reimporting
                  ? "⟳ Re-importing…"
                  : "↩ Re-import from processed/"}
              </button>
            </div>
          </div>
        )
      ) : (
        <div className="grid grid-cols-1 gap-2.5">
          {filteredTargets.map((target) => {
            const risk = computeRiskScore(target);
            const riskBarColor =
              risk.level === "CRITICAL"
                ? "bg-danger-500"
                : risk.level === "HIGH"
                  ? "bg-orange-500"
                  : risk.level === "MEDIUM"
                    ? "bg-warn-500"
                    : risk.level === "LOW"
                      ? "bg-success-500"
                      : "bg-accent";
            return (
              <div
                key={`${target.id}|${target.domain}`}
                className="relative bg-card rounded-xl border border-border cursor-pointer group tile-hover"
                onClick={() => onSelectTarget(target)}
              >
                <div className="tile-shine" />
                {/* Risk-level left accent bar */}
                <div
                  className={`absolute inset-y-0 left-0 w-[3px] ${riskBarColor} opacity-60`}
                />
                <div className="pl-5 pr-4 py-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="h-8 w-8 rounded-lg bg-secondary/50 flex items-center justify-center flex-shrink-0 group-hover:bg-primary-500/10 transition-colors">
                        <Globe className="w-4 h-4 text-muted-foreground/80 group-hover:text-primary-400 transition-colors" />
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-foreground group-hover:text-primary-300 transition-colors font-mono truncate">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.domain) }} />
                        </div>
                        <div className="text-[11px] text-muted-foreground mt-0.5 font-mono truncate">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.programName) }} />
                        </div>
                        <div className="flex flex-wrap gap-1.5 mt-1.5">
                          <span className="text-[11px] px-1.5 py-0.5 bg-secondary/60 text-muted-foreground rounded font-mono">
                            {target.subdomains?.length || 0} subs
                          </span>
                          <span className="text-[11px] px-1.5 py-0.5 bg-secondary/60 text-muted-foreground rounded font-mono">
                            {target.totalPorts} ports
                          </span>
                          {target.vulnerabilities?.length > 0 && (
                            <span className="text-[11px] px-1.5 py-0.5 bg-danger-500/10 text-danger-400 rounded font-mono border border-danger-500/15">
                              {target.vulnerabilities.length} vulns
                            </span>
                          )}
                          {getScannerTypes(target).map((st) => (
                            <span
                              key={st}
                              className="text-[10px] px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 rounded border border-cyan-500/15 font-mono"
                            >
                              {st}
                            </span>
                          ))}
                          {(target.tags || []).map((tag) => (
                            <span
                              key={tag}
                              className="text-[10px] px-1.5 py-0.5 bg-primary-500/10 text-primary-400 rounded border border-primary-500/15 font-mono"
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0 ml-3">
                      {risk.level !== "NONE" && (
                        <div className="text-right hidden sm:block">
                          <div
                            className={`text-xs font-bold font-mono ${
                              risk.level === "CRITICAL"
                                ? "text-danger-400"
                                : risk.level === "HIGH"
                                  ? "text-orange-400"
                                  : risk.level === "MEDIUM"
                                    ? "text-warn-400"
                                    : "text-success-400"
                            }`}
                          >
                            {Math.round(risk.score)}
                          </div>
                          <div className="w-14 h-[2px] bg-secondary/60 rounded mt-1 overflow-hidden">
                            <div
                              className={`h-full rounded risk-bar-fill ${riskBarColor}`}
                              style={{ width: `${Math.min(risk.score, 100)}%` }}
                            />
                          </div>
                        </div>
                      )}
                      <span
                        className={`text-[11px] px-2 py-1 rounded-md font-mono flex items-center gap-1.5 ${
                          target.status === "RUNNING"
                            ? "badge-running"
                            : target.status === "COMPLETED"
                              ? "badge-completed"
                              : "badge-pending"
                        }`}
                      >
                        {target.status === "RUNNING" && (
                          <span className="pulse-ring-dot" />
                        )}
                        {target.status}
                      </span>
                      <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/70 group-hover:text-primary-400 group-hover:translate-x-0.5 transition-all" />
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
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
  const [vulnPage, setVulnPage] = useState(0);
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());
  const debouncedVulnSearch = useDebounce(vulnSearch, 300);
  const [webNameFilter, setWebNameFilter] = useState("");
  const [webPortFilter, setWebPortFilter] = useState("");
  const [webStatusFilter, setWebStatusFilter] = useState("");
  const [webGroupSimilar, setWebGroupSimilar] = useState(false);
  const [notesExpanded, setNotesExpanded] = useState(false);
  const [notes, setNotes] = useState(target.notes || "");
  const [tags, setTags] = useState<string[]>(target.tags || []);
  const [tagInput, setTagInput] = useState("");
  const [notesSaving, setNotesSaving] = useState<
    "idle" | "saving" | "saved" | "error"
  >("idle");

  const saveNotesAndTags = async (nextNotes: string, nextTags: string[]) => {
    setNotesSaving("saving");
    try {
      await fetch(
        `http://localhost:5000/api/targets/${encodeURIComponent(target.id)}`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ notes: nextNotes, tags: nextTags }),
        },
      );
      setNotesSaving("saved");
      setTimeout(() => setNotesSaving("idle"), 1800);
    } catch {
      setNotesSaving("error");
      setTimeout(() => setNotesSaving("idle"), 2500);
    }
  };

  const addTag = () => {
    const t = tagInput.trim();
    if (!t || tags.includes(t)) {
      setTagInput("");
      return;
    }
    const next = [...tags, t];
    setTags(next);
    setTagInput("");
    saveNotesAndTags(notes, next);
  };

  const removeTag = (tag: string) => {
    const next = tags.filter((t: string) => t !== tag);
    setTags(next);
    saveNotesAndTags(notes, next);
  };

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
  const VULN_PAGE_SIZE = 30;

  const filteredVulns = useMemo(
    () =>
      target.vulnerabilities
        .filter((v) => {
          if (
            vulnSevFilter !== "ALL" &&
            (v.severity as string)?.toUpperCase() !== vulnSevFilter
          )
            return false;
          if (debouncedVulnSearch) {
            const q = debouncedVulnSearch.toLowerCase();
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
        ),
    [target.vulnerabilities, vulnSevFilter, debouncedVulnSearch],
  );

  const vulnTotalPages = Math.ceil(filteredVulns.length / VULN_PAGE_SIZE);
  const pagedVulns = useMemo(
    () =>
      filteredVulns.slice(
        vulnPage * VULN_PAGE_SIZE,
        (vulnPage + 1) * VULN_PAGE_SIZE,
      ),
    [filteredVulns, vulnPage],
  );

  // Reset page when filter changes
  React.useEffect(() => {
    setVulnPage(0);
  }, [vulnSevFilter, debouncedVulnSearch]);

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
      <div className="bg-card rounded-lg border border-border p-4">
        <div className="flex items-center gap-1.5 mb-3 text-xs font-mono">
          <Link
            to="/targets"
            className="text-muted-foreground hover:text-foreground/80 transition-colors"
          >
            targets
          </Link>
          <span className="text-muted-foreground/60">/</span>
          <span className="text-foreground/80"><span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.domain) }} /></span>
        </div>
        <div className="flex justify-between items-start">
          <div>
            <div className="text-sm font-bold text-foreground font-mono flex items-center gap-2 flex-wrap">
              <span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.domain) }} />
              <span className="text-xs bg-secondary text-muted-foreground px-2 py-0.5 rounded font-mono border border-border">
                <span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.programName) }} />
              </span>
              <div className="relative">
                <button
                  onClick={() => setShowDownloadMenu((v) => !v)}
                  className="text-xs bg-secondary hover:bg-accent text-muted-foreground border border-border px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors font-mono"
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
                    <div className="absolute left-0 top-8 z-20 bg-card border border-border rounded-lg py-1 w-44 shadow-lg">
                      <div className="px-3 py-1.5 text-[13px] text-muted-foreground/80 font-mono border-b border-border mb-1">
                        Export
                      </div>
                      <button
                        onClick={() => handleDownload("json")}
                        className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-primary-400">{}</span> JSON — full
                        target
                      </button>
                      <button
                        onClick={() => handleDownload("csv")}
                        className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-cyan-400">,</span> CSV —{" "}
                        {activeTab === "vulns"
                          ? "filtered vulns"
                          : "current tab"}
                      </button>
                      <button
                        onClick={() => handleDownload("txt")}
                        className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-green-400">#</span> TXT —{" "}
                        {activeTab === "vulns" ? "filtered vulns" : "flat list"}
                      </button>
                      {/* Raw source files — always available */}

                      <a
                        href={`${BRIDGE_BASE}/api/targets/${encodeURIComponent(target.id)}/raw-zip`}
                        download
                        onClick={() => setShowDownloadMenu(false)}
                        className="w-full block px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                      >
                        <span className="text-yellow-400">📦</span> ZIP — raw
                        source
                      </a>

                      {activeTab === "vulns" && (
                        <button
                          onClick={() => handleDownload("md")}
                          className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                        >
                          <div className="px-3 py-1.5 text-[13px] text-muted-foreground/80 font-mono border-t border-border mt-1 mb-1">
                            Vulnerabilities
                          </div>
                          <span className="text-purple-400">M↓</span> Markdown —
                          raw reports
                        </button>
                      )}
                      {gowitnessBundles.length > 0 && (
                        <>
                          <div className="px-3 py-1.5 text-[13px] text-muted-foreground/80 font-mono border-t border-border mt-1 mb-1">
                            GoWitness
                          </div>
                          {gowitnessBundles.map((bname) => (
                            <a
                              key={bname}
                              href={`${BRIDGE_BASE}/api/gowitness-bundle/${bname}/zip`}
                              download
                              onClick={() => setShowDownloadMenu(false)}
                              className="w-full block px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                            >
                              <span className="text-muted-foreground">🟪</span> ZIP —
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
            <div className="text-lg font-bold text-foreground font-mono">
              {scanMetrics.count}
            </div>
            <div className="text-xs text-muted-foreground font-mono">
              {scanMetrics.label}
            </div>
          </div>
        </div>
      </div>

      {/* Notes & Tags panel */}
      <div className="bg-card rounded-lg border border-border">
        <button
          className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-semibold font-mono text-muted-foreground hover:text-foreground/90 transition-colors"
          onClick={() => setNotesExpanded((prev: boolean) => !prev)}
        >
          <span className="flex items-center gap-2">
            <span className="text-primary-400">⌁</span> Notes &amp; Tags
            {tags.length > 0 && (
              <span className="flex gap-1">
                {tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-1.5 py-0 bg-primary-500/15 text-primary-400 border border-primary-500/25 rounded text-[10px] font-mono"
                  >
                    {tag}
                  </span>
                ))}
              </span>
            )}
            {notes && <span className="text-muted-foreground/80 italic">has notes</span>}
          </span>
          <span className="text-muted-foreground/80 text-[10px]">
            {notesExpanded ? "▲" : "▼"}
          </span>
        </button>
        {notesExpanded && (
          <div className="px-4 pb-4 space-y-3 border-t border-border pt-3">
            {/* Tags */}
            <div>
              <div className="text-[11px] font-mono text-muted-foreground mb-1.5 uppercase tracking-wider">
                Tags
              </div>
              <div className="flex flex-wrap gap-1.5 mb-2">
                {tags.map((tag) => (
                  <span
                    key={tag}
                    className="flex items-center gap-1 px-2 py-0.5 bg-primary-500/15 text-primary-400 border border-primary-500/25 rounded text-[11px] font-mono"
                  >
                    {tag}
                    <button
                      onClick={() => removeTag(tag)}
                      className="text-primary-600 hover:text-danger-400 transition-colors leading-none ml-0.5"
                      aria-label={`Remove tag ${tag}`}
                    >
                      ×
                    </button>
                  </span>
                ))}
                {tags.length === 0 && (
                  <span className="text-[11px] text-muted-foreground/80 font-mono italic">
                    No tags yet
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <input
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addTag();
                    }
                  }}
                  placeholder="Add tag…"
                  className="flex-1 bg-secondary border border-border rounded px-2.5 py-1 text-xs font-mono text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary-500 transition-colors"
                />
                <button
                  onClick={addTag}
                  disabled={!tagInput.trim()}
                  className="px-3 py-1 text-xs font-mono font-semibold bg-primary-600/20 text-primary-400 border border-primary-500/30 rounded hover:bg-primary-600/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  Add
                </button>
              </div>
            </div>
            {/* Notes */}
            <div>
              <div className="text-[11px] font-mono text-muted-foreground mb-1.5 uppercase tracking-wider">
                Notes
              </div>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={4}
                placeholder="Add reconnaissance notes, scope exclusions, interesting findings…"
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-xs font-mono text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary-500 transition-colors resize-y"
              />
              <div className="flex items-center justify-between mt-1.5">
                <span
                  className={`text-[11px] font-mono ${notesSaving === "saved" ? "text-success-400" : notesSaving === "error" ? "text-danger-400" : notesSaving === "saving" ? "text-muted-foreground" : "text-transparent"}`}
                >
                  {notesSaving === "saving"
                    ? "Saving…"
                    : notesSaving === "saved"
                      ? "Saved"
                      : notesSaving === "error"
                        ? "Save failed"
                        : "."}
                </span>
                <button
                  onClick={() => saveNotesAndTags(notes, tags)}
                  disabled={notesSaving === "saving"}
                  className="px-3 py-1 text-xs font-mono font-semibold bg-secondary text-foreground/80 border border-border rounded hover:bg-accent disabled:opacity-40 transition-colors"
                >
                  Save notes
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Tab bar */}
      <div className="flex gap-0 border-b border-border">
        {/* Subdomain tab */}
        {isSubdomainScan && (
          <button
            onClick={() => setActiveTab("subdomains")}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors font-mono ${
              activeTab === "subdomains"
                ? "border-primary-500 text-primary-400"
                : "border-transparent text-muted-foreground hover:text-foreground/90"
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
                : "border-transparent text-muted-foreground hover:text-foreground/90"
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
                : "border-transparent text-muted-foreground hover:text-foreground/90"
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
                : "border-transparent text-muted-foreground hover:text-foreground/90"
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
                : "border-transparent text-muted-foreground hover:text-foreground/90"
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
                : "border-transparent text-muted-foreground hover:text-foreground/90"
            }`}
          >
            Topology
          </button>
        )}
      </div>

      {/* Subdomains view */}
      {activeTab === "subdomains" && (
        <div className="space-y-3">
          <div className="bg-card/60 border border-border/40 rounded-lg px-4 py-3">
            <p className="text-xs text-muted-foreground font-mono">
              💡 Run{" "}
              <code className="text-cyan-400 bg-background px-1.5 py-0.5 rounded">
                httpx
              </code>{" "}
              or{" "}
              <code className="text-cyan-400 bg-background px-1.5 py-0.5 rounded">
                gowitness
              </code>{" "}
              on these subdomains for HTTP probing &amp; screenshots.
            </p>
          </div>
          {target.subdomains.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground/80 bg-card/40 rounded-lg border border-border/40 border-dashed">
              <Globe className="w-8 h-8 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-mono">No subdomains found yet</p>
            </div>
          ) : (
            <div className="bg-card rounded-lg border border-border overflow-hidden">
              <table className="w-full text-left">
                <thead className="border-b border-border">
                  <tr className="text-[13px] text-muted-foreground font-mono">
                    <th className="px-4 py-2.5 font-medium">IP</th>
                    <th className="px-4 py-2.5 font-medium">Location</th>
                  </tr>
                </thead>
                <tbody>
                  {target.subdomains.map((sub) => (
                    <tr
                      key={sub.id}
                      className="border-b border-border/50 hover:bg-secondary/20 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-sm text-cyan-300">
                        <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.hostname) }} />
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                        {sub.ip ? <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.ip) }} /> : "—"}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {sub.location ? <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.location) }} /> : "—"}
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
          <div className="flex flex-wrap gap-2 bg-card border border-border rounded-lg px-3 py-2.5 items-center">
            <Filter className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
            <input
              type="text"
              placeholder="Filter by name…"
              value={webNameFilter}
              onChange={(e) => setWebNameFilter(e.target.value)}
              className="bg-secondary border border-border rounded px-2.5 py-1 text-xs text-foreground font-mono placeholder-muted-foreground focus:outline-none focus:border-cyan-500 w-44"
            />
            <input
              type="text"
              placeholder="Filter by port (e.g. 443)"
              value={webPortFilter}
              onChange={(e) => setWebPortFilter(e.target.value)}
              className="bg-secondary border border-border rounded px-2.5 py-1 text-xs text-foreground font-mono placeholder-muted-foreground focus:outline-none focus:border-cyan-500 w-44"
            />
            <div className="flex items-center gap-1">
              {(["2xx", "3xx", "4xx", "5xx"] as const).map((range) => {
                const active = webStatusFilter === range;
                const colors: Record<string, string> = {
                  "2xx": active
                    ? "bg-emerald-600/30 border-emerald-500/60 text-emerald-300"
                    : "border-border text-muted-foreground hover:border-emerald-500/40 hover:text-emerald-400",
                  "3xx": active
                    ? "bg-yellow-600/30 border-yellow-500/60 text-yellow-300"
                    : "border-border text-muted-foreground hover:border-yellow-500/40 hover:text-yellow-400",
                  "4xx": active
                    ? "bg-red-600/30 border-red-500/60 text-red-300"
                    : "border-border text-muted-foreground hover:border-red-500/40 hover:text-red-400",
                  "5xx": active
                    ? "bg-purple-600/30 border-purple-500/60 text-purple-300"
                    : "border-border text-muted-foreground hover:border-purple-500/40 hover:text-purple-400",
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
                className="bg-secondary border border-border rounded px-2 py-1 text-xs text-foreground font-mono placeholder-muted-foreground focus:outline-none focus:border-cyan-500 w-16"
              />
            </div>
            {(webNameFilter || webPortFilter || webStatusFilter) && (
              <button
                onClick={() => {
                  setWebNameFilter("");
                  setWebPortFilter("");
                  setWebStatusFilter("");
                }}
                className="text-xs text-muted-foreground hover:text-foreground transition-colors font-mono flex items-center gap-1"
              >
                <X className="w-3 h-3" /> clear
              </button>
            )}
            <button
              onClick={() => setWebGroupSimilar(v => !v)}
              className={`ml-2 text-xs font-mono flex items-center gap-1 px-2 py-1 rounded border transition-colors ${
                webGroupSimilar
                  ? "border-primary/60 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/40 hover:text-foreground"
              }`}
              title="Group cards with matching page titles together"
            >
              <svg className="w-3 h-3" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="1" y="1" width="4" height="4" rx="0.5"/>
                <rect x="7" y="1" width="4" height="4" rx="0.5"/>
                <rect x="1" y="7" width="4" height="4" rx="0.5"/>
                <rect x="7" y="7" width="4" height="4" rx="0.5"/>
              </svg>
              Group similar
            </button>
            <span className="ml-auto text-[11px] text-muted-foreground/80 font-mono">
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
          {(() => {
            const filteredSubs = target.subdomains.filter((sub) => {
              const nameOk =
                !webNameFilter ||
                sub.hostname.toLowerCase().includes(webNameFilter.toLowerCase());
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
            });
            const allCodesZero = target.subdomains.every((s) => !(s.statusCode ?? 0));
            if (filteredSubs.length === 0) {
              return (
                <div className="p-10 text-center text-muted-foreground/60 bg-card/40 rounded-lg border border-border/40 border-dashed">
                  <Globe className="w-7 h-7 mx-auto mb-2 opacity-20" />
                  <p className="text-sm font-mono mb-1">No results match this filter</p>
                  {webStatusFilter && allCodesZero && (
                    <p className="text-[11px] font-mono text-muted-foreground/40">
                      HTTP status codes unavailable — run httpx with <span className="text-primary-400">-json</span> output to populate them
                    </p>
                  )}
                </div>
              );
            }
            // Build a card renderer shared by both flat and grouped views
            const renderCard = (sub: typeof filteredSubs[0]) => {
                const statusCode = sub.statusCode ?? 0;
                const title = sub.title ?? "";
                // Screenshot path stored as relative /api/screenshots/... — prefix with bridge host
                const screenshotSrc = sub.screenshot
                  ? sub.screenshot.startsWith("/api/")
                    ? `${BRIDGE_BASE}${sub.screenshot}`
                    : sub.screenshot
                  : null;
                // Solid accent colors from DESIGN.md: accent-green/yellow/red
                const statusAccent =
                  statusCode >= 200 && statusCode < 300
                    ? "#59d499"
                    : statusCode >= 300 && statusCode < 400
                      ? "#ffc533"
                      : statusCode >= 400
                        ? "#ff6161"
                        : "#6a6b6c";
                const statusBg =
                  statusCode >= 200 && statusCode < 300
                    ? "rgba(89,212,153,0.12)"
                    : statusCode >= 300 && statusCode < 400
                      ? "rgba(255,197,51,0.12)"
                      : statusCode >= 400
                        ? "rgba(255,97,97,0.12)"
                        : "rgba(106,107,108,0.12)";
                return (
                  <div
                    key={sub.id}
                    className="bg-card rounded-lg overflow-hidden border border-border hover:border-border transition-colors group card-hover"
                  >
                    <div className="h-40 bg-background relative overflow-hidden">
                      {/* Placeholder always rendered underneath */}
                      <div className="absolute inset-0 flex items-center justify-center text-muted-foreground/60">
                        <Globe className="w-7 h-7 opacity-30" />
                      </div>
                      {/* Screenshot overlays placeholder; hidden on load error */}
                      {screenshotSrc && (
                        <img
                          src={screenshotSrc}
                          alt={sub.hostname}
                          className="absolute inset-0 w-full h-full object-cover opacity-70 group-hover:opacity-100 transition-opacity"
                          onError={(e) => { e.currentTarget.style.display = "none"; }}
                        />
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
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.hostname) }} />
                        </a>
                      ) : (
                        <h4
                          className="font-bold text-foreground truncate text-sm mb-0.5 font-mono group-hover:text-primary-300 transition-colors"
                          title={sub.hostname}
                        >
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.hostname) }} />
                        </h4>
                      )}
                      {/* Page title */}
                      {title && (
                        <p
                          className="text-[14px] text-muted-foreground truncate mb-1.5 italic"
                          title={title}
                          dangerouslySetInnerHTML={{ __html: ansiToHtml(title) }}
                        />
                      )}
                      <div className="flex items-center gap-2 text-[14px] text-muted-foreground mb-2">
                        <span className="truncate max-w-[120px]">
                          {sub.location
                            ? <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.location) }} />
                            : sub.ip !== sub.hostname
                              ? <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.ip) }} />
                              : "—"}
                        </span>
                      </div>
                      {sub.technologies.length > 0 && (
                        <div className="flex flex-wrap gap-1 mb-2">
                          {sub.technologies.slice(0, 4).map((tech) => (
                            <span
                              key={tech}
                              className="px-1.5 py-0.5 bg-secondary rounded text-[13px] text-muted-foreground border border-border/30 font-mono"
                              dangerouslySetInnerHTML={{ __html: ansiToHtml(tech) }}
                            />
                          ))}
                          {sub.technologies.length > 4 && (
                            <span className="px-1.5 py-0.5 text-[13px] text-muted-foreground/80 font-mono">
                              +{sub.technologies.length - 4}
                            </span>
                          )}
                        </div>
                      )}
                      <div className="flex flex-wrap gap-1 items-center">
                        {sub.ports.map((p) => (
                          <span
                            key={p.port}
                            className={`text-[13px] px-1.5 py-0.5 rounded border font-mono ${
                              p.service === "https" || p.port === 443
                                ? "border-cyan-500/30 text-cyan-400 bg-cyan-500/10"
                                : p.port === 80
                                  ? "border-success-500/30 text-success-400 bg-success-500/10"
                                  : "border-border text-muted-foreground"
                            }`}
                          >
                            {p.port}/<span dangerouslySetInnerHTML={{ __html: ansiToHtml(p.service) }} />
                          </span>
                        ))}
                        {statusCode > 0 && (
                          <span
                            className="text-[13px] px-1.5 py-0.5 rounded border font-mono"
                            style={{ color: statusAccent, borderColor: `${statusAccent}55`, backgroundColor: statusBg }}
                          >
                            {statusCode}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
            };

            if (webGroupSimilar) {
              // Tech-family definitions — checked in order, first match wins
              const FAMILIES: { name: string; kw: string[] }[] = [
                { name: "Microsoft IIS",     kw: ["iis", "iisstart", "microsoft-iis", "windows server", "asp.net"] },
                { name: "Apache Tomcat",     kw: ["tomcat"] },
                { name: "Apache HTTP",       kw: ["it works", "apache http", "apache/", "apache2 default"] },
                { name: "nginx",             kw: ["nginx", "welcome to nginx"] },
                { name: "Exchange / OWA",    kw: ["exchange", "outlook web", "owa"] },
                { name: "SharePoint",        kw: ["sharepoint"] },
                { name: "Cisco",             kw: ["cisco", "anyconnect", "ios xe", "webvpn", "asa"] },
                { name: "Fortinet",          kw: ["fortinet", "fortigate", "fortiweb", "fortimanager", "fortianalyzer"] },
                { name: "Palo Alto",         kw: ["palo alto", "globalprotect", "pan-os"] },
                { name: "Juniper",           kw: ["juniper", "junos", "pulse secure", "ivanti"] },
                { name: "VMware",            kw: ["vmware", "vsphere", "esxi", "vcenter", "horizon"] },
                { name: "Grafana",           kw: ["grafana"] },
                { name: "Jenkins",           kw: ["jenkins"] },
                { name: "GitLab",            kw: ["gitlab"] },
                { name: "Kubernetes",        kw: ["kubernetes", "rancher", "openshift", "k8s"] },
                { name: "pfSense / OPNsense",kw: ["pfsense", "opnsense"] },
                { name: "Splunk",            kw: ["splunk"] },
                { name: "F5 BIG-IP",         kw: ["big-ip", "f5", "bigip"] },
                { name: "Citrix",            kw: ["citrix", "netscaler", "storefront"] },
              ];

              const getFamily = (sub: typeof filteredSubs[0]): string => {
                const hay = [(sub.title ?? ""), ...(sub.technologies ?? [])].join(" ").toLowerCase();
                for (const f of FAMILIES) {
                  if (f.kw.some(k => hay.includes(k))) return f.name;
                }
                return "Other";
              };

              // Build family → title → subs hierarchy
              type SubList = typeof filteredSubs;
              const familyMap = new Map<string, Map<string, SubList>>();
              for (const sub of filteredSubs) {
                const family = getFamily(sub);
                const titleKey = (sub.title ?? "").trim() || "— no title —";
                if (!familyMap.has(family)) familyMap.set(family, new Map());
                const tm = familyMap.get(family)!;
                if (!tm.has(titleKey)) tm.set(titleKey, []);
                tm.get(titleKey)!.push(sub);
              }

              // Sort families by total host count (largest first)
              const families = [...familyMap.entries()]
                .map(([name, titleMap]) => ({
                  name,
                  titleMap,
                  total: [...titleMap.values()].reduce((s, a) => s + a.length, 0),
                }))
                .sort((a, b) => b.total - a.total);

              return (
                <div className="space-y-8">
                  {families.map(({ name: familyName, titleMap, total }) => {
                    // Sort title sub-groups within a family by count, largest first
                    const titleGroups = [...titleMap.entries()].sort((a, b) => b[1].length - a[1].length);
                    return (
                      <div key={familyName}>
                        {/* Family header */}
                        <div className="flex items-center gap-2 mb-3">
                          <span className="text-[11px] font-mono font-semibold tracking-widest uppercase text-muted-foreground/80 px-2 py-0.5 rounded bg-secondary border border-border/60">
                            {familyName}
                          </span>
                          <span className="text-[11px] font-mono text-muted-foreground/40">{total} hosts</span>
                          <div className="flex-1 border-t border-border/40" />
                        </div>
                        {/* Title sub-groups */}
                        <div className="space-y-4 pl-3 border-l border-border/20">
                          {titleGroups.map(([titleKey, subs]) => (
                            <div key={titleKey}>
                              {titleGroups.length > 1 && (
                                <div className="flex items-center gap-2 mb-2">
                                  <span className="text-[11px] font-mono text-muted-foreground/50 truncate max-w-[55%] italic" title={titleKey}>
                                    {titleKey}
                                  </span>
                                  <span className="text-[10px] font-mono text-muted-foreground/30">({subs.length})</span>
                                  <div className="flex-1 border-t border-border/20" />
                                </div>
                              )}
                              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                {subs.map(renderCard)}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              );
            }

            return (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredSubs.map(renderCard)}
              </div>
            );
          })()}
        </div>
      )}

      {/* Ports view */}
      {activeTab === "ports" && (
        <div className="space-y-3">
          {target.subdomains.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground/80 bg-card/40 rounded-lg border border-border/40 border-dashed">
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
                  className="bg-card rounded-lg border border-border p-4"
                >
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <h4 className="font-bold text-foreground text-sm font-mono">
                        <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.hostname) }} />
                      </h4>
                      {sub.ip && (
                        <p className="text-[13px] text-muted-foreground font-mono mt-0.5">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(sub.ip) }} />
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
                          className="bg-background rounded-lg border border-border/60 p-2.5"
                        >
                          <div className="font-mono text-sm text-foreground">
                            {portNum}
                            <span className="text-muted-foreground/80">/<span dangerouslySetInnerHTML={{ __html: ansiToHtml(svcName) }} /></span>
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
                        : "bg-card border-border text-muted-foreground hover:border-border hover:text-foreground"
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
              className="flex-1 sm:max-w-xs bg-card border border-border rounded px-3 py-1.5 text-[13px] text-foreground/90 font-mono placeholder-muted-foreground focus:outline-none focus:border-primary-500/50"
            />
          </div>

          {filteredVulns.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground/80 bg-card/40 rounded-lg border border-border/40 border-dashed">
              <ShieldAlert className="w-8 h-8 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-mono">No vulnerabilities match</p>
            </div>
          ) : (
            pagedVulns.map((vuln, idx) => {
              const key = `${vuln.id}:${vuln.path}:${idx}`;
              const expanded = expandedVulns.has(key);
              const rawContent = (vuln as any).rawContent as string | undefined;
              return (
                <div
                  key={key}
                  className={`bg-card rounded-lg border border-border ${
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
                      <h4 className="text-foreground font-semibold text-sm flex items-center gap-2 flex-wrap">
                        <span dangerouslySetInnerHTML={{ __html: ansiToHtml(vuln.name) }} />
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
                        <p className="text-muted-foreground text-xs mt-1.5">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(vuln.description) }} />
                        </p>
                      )}
                      {vuln.path && (
                        <p className="text-muted-foreground text-[13px] font-mono mt-2 bg-background inline-block px-2 py-1 rounded border border-border/40 break-all">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(vuln.path) }} />
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
                        className="p-1.5 text-muted-foreground/80 hover:text-foreground/80 transition-colors"
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
                              : "text-muted-foreground/80 hover:text-foreground/80"
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
                    <div className="border-t border-border px-4 py-3 bg-background/40 rounded-b-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[13px] text-muted-foreground font-mono">
                          Raw output
                        </span>
                        <button
                          onClick={() =>
                            navigator.clipboard.writeText(rawContent)
                          }
                          className="text-[13px] text-muted-foreground hover:text-primary-400 transition-colors font-mono flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" /> Copy raw
                        </button>
                      </div>
                      <pre
                        className="text-xs text-foreground/80 font-mono whitespace-pre-wrap leading-relaxed bg-background rounded border border-border p-3 overflow-x-auto max-h-96"
                        dangerouslySetInnerHTML={{ __html: ansiToHtml(rawContent) }}
                      />
                    </div>
                  )}
                </div>
              );
            })
          )}
          {/* Vuln pagination */}
          {filteredVulns.length > VULN_PAGE_SIZE && (
            <div className="flex items-center justify-between pt-2 mt-1 border-t border-border/40">
              <span className="text-[11px] font-mono text-muted-foreground/80">
                {filteredVulns.length} vulns | page {vulnPage + 1}/
                {vulnTotalPages}
              </span>
              <div className="flex items-center gap-1">
                <button
                  className="page-btn"
                  onClick={() => setVulnPage(0)}
                  disabled={vulnPage === 0}
                >
                  &lt;&lt;
                </button>
                <button
                  className="page-btn"
                  onClick={() => setVulnPage((p) => p - 1)}
                  disabled={vulnPage === 0}
                >
                  &lt;
                </button>
                {Array.from({ length: Math.min(vulnTotalPages, 5) }, (_, i) => {
                  const p =
                    vulnTotalPages <= 5
                      ? i
                      : Math.max(
                          0,
                          Math.min(vulnTotalPages - 5, vulnPage - 2),
                        ) + i;
                  return (
                    <button
                      key={p}
                      className={`page-btn ${p === vulnPage ? "page-btn-active" : ""}`}
                      onClick={() => setVulnPage(p)}
                    >
                      {p + 1}
                    </button>
                  );
                })}
                <button
                  className="page-btn"
                  onClick={() => setVulnPage((p) => p + 1)}
                  disabled={vulnPage >= vulnTotalPages - 1}
                >
                  &gt;
                </button>
                <button
                  className="page-btn"
                  onClick={() => setVulnPage(vulnTotalPages - 1)}
                  disabled={vulnPage >= vulnTotalPages - 1}
                >
                  &gt;&gt;
                </button>
              </div>
            </div>
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
                    <span dangerouslySetInnerHTML={{ __html: ansiToHtml(domain) }} />
                  </span>
                </div>
                <div className="bg-background rounded-lg border border-border p-4 overflow-x-auto">
                  <pre
                    className="text-xs text-foreground/80 font-mono whitespace-pre-wrap leading-relaxed"
                    dangerouslySetInnerHTML={{ __html: ansiToHtml(text) }}
                  />
                </div>
              </div>
            ))
          ) : (
            <div className="bg-background rounded-lg border border-border p-4">
              <pre
                className="text-xs text-cyan-300 font-mono whitespace-pre-wrap leading-relaxed"
                dangerouslySetInnerHTML={{
                  __html: target.subdomains.length > 0
                    ? target.subdomains.map((s) => ansiToHtml(s.hostname)).join("\n")
                    : "No output available"
                }}
              />
            </div>
          )}
        </div>
      )}

      {/* Topology map */}
      {activeTab === "map" && (
        <div className="bg-card p-4 rounded-lg border border-border min-h-[400px]">
          <TopologyGraph target={target} />
        </div>
      )}
    </div>
  );
};

// ------------- Layout -------------

const SCANS_GROUP_PATHS = ["/scans", "/quickscan"];

const Sidebar = ({ role }: { role?: string | null }) => {
  const location = useLocation();
  const [expandedGroups, setExpandedGroups] = useState<string[]>(() =>
    SCANS_GROUP_PATHS.some((p) => location.pathname.startsWith(p))
      ? ["scans"]
      : [],
  );

  useEffect(() => {
    if (
      SCANS_GROUP_PATHS.some((p) => location.pathname.startsWith(p)) &&
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
    icon: React.ElementType;
    label: string;
    badge?: string;
  }) => {
    const active = isActiveLink(to);
    return (
      <Button
        variant="ghost"
        size="sm"
        asChild
        className={cn(
          "w-full justify-start gap-2.5 px-2.5 h-8 text-[13px] font-normal rounded-md mb-0.5",
          active
            ? "bg-primary/10 text-primary border-l-2 border-primary pl-[9px] rounded-l-none"
            : "text-muted-foreground hover:text-foreground hover:bg-accent",
        )}
      >
        <Link to={to}>
          <Icon size={15} className="flex-shrink-0" />
          <span className="flex-1 text-left">{label}</span>
          {badge && (
            <Badge
              variant="danger"
              className="text-[10px] px-1.5 py-0 h-4 font-mono"
            >
              {badge}
            </Badge>
          )}
        </Link>
      </Button>
    );
  };

  const NavGroup = ({
    groupKey,
    icon: Icon,
    label,
    children,
    matchPaths,
  }: {
    groupKey: string;
    icon: React.ElementType;
    label: string;
    children: React.ReactNode;
    matchPaths?: string[];
  }) => {
    const expanded = expandedGroups.includes(groupKey);
    const anyChildActive = (matchPaths ?? [`/${groupKey}`]).some((p) =>
      location.pathname.startsWith(p),
    );
    return (
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => toggleGroup(groupKey)}
          className={cn(
            "w-full justify-start gap-2.5 px-2.5 h-8 text-[13px] font-normal rounded-md mb-0.5",
            anyChildActive
              ? "bg-primary/10 text-primary border-l-2 border-primary pl-[9px] rounded-l-none"
              : "text-muted-foreground hover:text-foreground hover:bg-accent",
          )}
        >
          <Icon size={15} className="flex-shrink-0" />
          <span className="flex-1 text-left">{label}</span>
          <ChevronDown
            size={13}
            className={cn(
              "text-muted-foreground/60 transition-transform flex-shrink-0",
              expanded && "rotate-180",
            )}
          />
        </Button>
        {expanded && (
          <div className="ml-3 pl-3 border-l border-border/60 mb-1 space-y-0.5">
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
      <Button
        variant="ghost"
        size="sm"
        asChild
        className={cn(
          "w-full justify-start gap-2 px-2 h-7 text-[12px] font-normal rounded-md",
          active
            ? "text-primary bg-primary/10"
            : "text-muted-foreground hover:text-foreground hover:bg-accent",
        )}
      >
        <Link to={to}>
          <span
            className={cn(
              "w-1.5 h-1.5 rounded-full flex-shrink-0",
              active ? "bg-primary" : "bg-muted-foreground/40",
            )}
          />
          {label}
        </Link>
      </Button>
    );
  };

  return (
    <TooltipProvider delayDuration={0}>
      <aside className="w-56 bg-sidebar border-r border-sidebar-border h-screen fixed left-0 top-0 flex flex-col z-30">
        {/* Logo */}
        <div className="px-4 pt-4 pb-3 flex items-center gap-2.5">
          <BinocularsSkullLogo size={28} />
          <div>
            <div className="text-[15px] font-bold leading-none tracking-wide gradient-text">
              AXDASH
            </div>
            <div className="text-[10px] text-muted-foreground/60 font-mono mt-0.5 uppercase tracking-widest">
              Recon Platform
            </div>
          </div>
        </div>

        <Separator className="bg-sidebar-border" />

        {/* Nav */}
        <ScrollArea className="flex-1 py-3">
          <div className="px-2 space-y-4">
            {/* Recon */}
            <div>
              <p className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground/40 font-mono mb-1.5 px-2.5">
                Recon
              </p>
              <NavLink to="/" icon={LayoutDashboard} label="Dashboard" />
              <NavLink to="/targets" icon={TargetIcon} label="Targets" />
              <NavLink to="/vulns" icon={ShieldAlert} label="Vulnerabilities" />
              <NavLink to="/triage" icon={Flag} label="Findings Triage" />
              <NavLink to="/inventory" icon={Cpu} label="CVE Inventory" />
              <NavLink to="/projects" icon={FolderKanban} label="Projects" />
              <NavLink to="/workflow" icon={Layers} label="Workflows" />
              <NavGroup
                groupKey="scans"
                icon={Activity}
                label="Scans"
                matchPaths={SCANS_GROUP_PATHS}
              >
                <SubLink to="/quickscan" label="Quick Scan" />
                <SubLink to="/scans?tab=launcher" label="Launch Scan" />
                <SubLink to="/scans?tab=active" label="Active / Monitor" />
                <SubLink to="/scans?tab=output" label="Output Viewer" />
              </NavGroup>
            </div>

            <Separator className="bg-sidebar-border" />

            {/* Infrastructure */}
            <div>
              <p className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground/40 font-mono mb-1.5 px-2.5">
                Infrastructure
              </p>
              <NavLink to="/fleet" icon={Server} label="Fleet" />
              <NavLink to="/wordlists" icon={Database} label="Wordlists" />
              <NavLink to="/settings" icon={SettingsIcon} label="Settings" />
            </div>

            <Separator className="bg-sidebar-border" />

            {/* Account */}
            <div>
              <p className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground/40 font-mono mb-1.5 px-2.5">
                Account
              </p>
              <NavLink to="/profile" icon={User} label="My Profile" />
              {(role === "admin" || role === null) && (
                <NavLink to="/admin" icon={Shield} label="Admin" />
              )}
              <NavLink to="/docs" icon={BookOpen} label="Documentation" />
            </div>
          </div>
        </ScrollArea>
      </aside>
    </TooltipProvider>
  );
};

const Header = ({
  unreadCount = 0,
  onBellClick,
  onLogout,
  username,
}: {
  unreadCount?: number;
  onBellClick?: () => void;
  onLogout?: () => void;
  username?: string | null;
}) => {
  const location = useLocation();
  const pageLabels: Record<string, string> = {
    "/": "Dashboard",
    "/targets": "Targets",
    "/vulns": "Vulnerabilities",
    "/triage": "Findings Triage",
    "/workflow": "Workflows",
    "/scans": "Scans",
    "/fleet": "Fleet",
    "/wordlists": "Wordlists",
    "/docs": "Documentation",
    "/settings": "Settings",
    "/profile": "My Profile",
    "/admin": "Admin Panel",
  };
  const currentPage = Object.entries(pageLabels).find(([path]) =>
    path === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(path),
  );
  const pageTitle = currentPage?.[1] ?? "Dashboard";
  const [theme, setThemeState] = useState<Theme>(() => getTheme());
  const handleToggleTheme = () => setThemeState(toggleTheme());

  return (
    <header className="h-12 bg-background border-b border-border sticky top-0 z-20 flex items-center justify-between px-5 ml-56">
      {/* Left: breadcrumb */}
      <div className="flex items-center gap-1.5">
        <span className="text-muted-foreground/50 font-mono text-xs">ax /</span>
        <span className="text-foreground text-xs font-mono font-medium">
          {pageTitle}
        </span>
      </div>

      {/* Right: status + actions */}
      <div className="flex items-center gap-2">
        {/* Bridge status pill */}
        <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-success-500/10 border border-success-500/20">
          <span className="w-1.5 h-1.5 rounded-full bg-success-400 animate-pulse" />
          <span className="text-success-400 text-[11px] font-mono">online</span>
        </div>

        {/* Notifications */}
        <Button
          variant="ghost"
          size="icon"
          onClick={handleToggleTheme}
          title={
            theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
          }
          className="h-8 w-8 text-muted-foreground hover:text-foreground"
        >
          {theme === "dark" ? (
            <Sun className="w-4 h-4" />
          ) : (
            <Moon className="w-4 h-4" />
          )}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          onClick={onBellClick}
          className="relative h-8 w-8 text-muted-foreground hover:text-foreground"
        >
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <Badge
              variant="danger"
              className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 text-[9px] px-1 font-mono flex items-center justify-center rounded-full"
            >
              {unreadCount > 9 ? "9+" : unreadCount}
            </Badge>
          )}
        </Button>

        {/* User menu */}
        {username && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="h-8 gap-2 px-2 text-xs font-mono text-muted-foreground hover:text-foreground"
              >
                <Avatar className="h-6 w-6">
                  <AvatarFallback className="bg-primary/20 text-primary text-[10px] font-bold uppercase">
                    {username[0]}
                  </AvatarFallback>
                </Avatar>
                <span className="max-w-[72px] truncate">{username}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-44">
              <DropdownMenuLabel className="font-mono">
                {username}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link to="/profile" className="cursor-pointer">
                  <User className="mr-2 h-3.5 w-3.5" />
                  My Profile
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link to="/settings" className="cursor-pointer">
                  <SettingsIcon className="mr-2 h-3.5 w-3.5" />
                  Settings
                </Link>
              </DropdownMenuItem>
              {onLogout && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    onClick={onLogout}
                    className="text-destructive focus:text-destructive cursor-pointer"
                  >
                    <LogOut className="mr-2 h-3.5 w-3.5" />
                    Sign out
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </header>
  );
};

// ------------- Main App Wrapper -------------

// ──────────────────────────────────────────────────────────────────────────────
// All-Vulnerabilities page
// ──────────────────────────────────────────────────────────────────────────────
const VULNS_PAGE_SIZE = 50;

const VulnsPage = ({ targets }: { targets: Target[] }) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const sevParam = searchParams.get("sev")?.toUpperCase() || "ALL";
  const [sevFilter, setSevFilter] = useState(sevParam);
  const [searchQ, setSearchQ] = useState("");
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());
  const [vulnsPage, setVulnsPage] = useState(0);
  const [projects, setProjects] = useState<AxProject[]>([]);
  const [projectFilter, setProjectFilter] = useState("all");
  const activeProject = useActiveProject();
  useEffect(() => {
    if (activeProject) setProjectFilter(activeProject);
  }, [activeProject]);
  const [showDownloadMenu, setShowDownloadMenu] = useState(false);

  // Keep state in sync when URL param changes (e.g. dashboard card click)
  useEffect(() => {
    setSevFilter(searchParams.get("sev")?.toUpperCase() || "ALL");
    setVulnsPage(0);
  }, [searchParams]);

  // Load projects for filter dropdown
  useEffect(() => {
    fetch("http://localhost:5000/api/projects/mine", { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then((d) => setProjects(Array.isArray(d) ? d : Object.values(d)))
      .catch(() => {});
  }, []);

  // Filter targets by selected project — fetch server-side by projectToken
  const [projectTargets, setProjectTargets] = useState<typeof targets | null>(null);
  useEffect(() => {
    if (projectFilter === "all") {
      setProjectTargets(null);
      return;
    }
    fetch(`http://localhost:5000/api/targets?projectToken=${encodeURIComponent(projectFilter)}`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then((data) => setProjectTargets(Array.isArray(data) ? data : []))
      .catch(() => setProjectTargets([]));
  }, [projectFilter]);

  const vulnSourceTargets = projectFilter !== "all" && projectTargets !== null ? projectTargets : targets;

  // Flatten all vulns from filtered targets
  const allVulns = vulnSourceTargets.flatMap((target) =>
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

  const totalVulnsPages = Math.ceil(filtered.length / VULNS_PAGE_SIZE);
  const pagedVulns = filtered.slice(vulnsPage * VULNS_PAGE_SIZE, (vulnsPage + 1) * VULNS_PAGE_SIZE);

  const csvEscape = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;

  const handleDownload = (format: "json" | "csv" | "txt") => {
    let content = "";
    let mime = "text/plain";
    const stamp = new Date().toISOString().slice(0, 10);
    let filename = `vulnerabilities-${sevFilter.toLowerCase()}-${stamp}`;

    if (format === "json") {
      content = JSON.stringify(filtered, null, 2);
      filename += ".json";
      mime = "application/json";
    } else if (format === "csv") {
      content =
        "target,name,severity,description,path\n" +
        filtered
          .map((v) =>
            [
              csvEscape((v as any).targetDomain),
              csvEscape(v.name),
              csvEscape(v.severity),
              csvEscape(v.description),
              csvEscape(v.path),
            ].join(","),
          )
          .join("\n");
      filename += ".csv";
      mime = "text/csv";
    } else {
      content = filtered
        .map(
          (v) =>
            `[${v.severity}] ${(v as any).targetDomain} — ${v.name}${v.path ? " - " + v.path : ""}`,
        )
        .join("\n");
      filename += ".txt";
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
      return "bg-card border-border text-muted-foreground hover:border-border hover:text-foreground";
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

  const affectedTargets = vulnSourceTargets.filter(
    (t) => (t.vulnerabilities || []).length > 0,
  ).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-foreground font-mono flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-danger-400" />
            Vulnerabilities
          </h1>
          <p className="text-[13px] text-muted-foreground font-mono mt-0.5">
            {filtered.length} finding{filtered.length !== 1 ? "s" : ""} across{" "}
            {affectedTargets} target{affectedTargets !== 1 ? "s" : ""}
          </p>
        </div>
        <div className="relative">
          <button
            onClick={() => setShowDownloadMenu((v) => !v)}
            className="text-xs bg-secondary hover:bg-accent text-muted-foreground border border-border px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors font-mono"
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
              <div className="absolute right-0 top-8 z-20 bg-card border border-border rounded-lg py-1 w-48 shadow-lg">
                <div className="px-3 py-1.5 text-[13px] text-muted-foreground/80 font-mono border-b border-border mb-1">
                  Export filtered ({filtered.length})
                </div>
                <button
                  onClick={() => handleDownload("json")}
                  className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                >
                  <span className="text-primary-400">{"{}"}</span> JSON
                </button>
                <button
                  onClick={() => handleDownload("csv")}
                  className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                >
                  <span className="text-cyan-400">,</span> CSV
                </button>
                <button
                  onClick={() => handleDownload("txt")}
                  className="w-full text-left px-3 py-2 text-xs text-foreground/80 hover:bg-secondary hover:text-foreground transition-colors font-mono flex items-center gap-2"
                >
                  <span className="text-green-400">#</span> TXT
                </button>
              </div>
            </>
          )}
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
            className="w-full bg-card border border-border rounded px-3 py-1.5 text-[13px] text-foreground/90 font-mono placeholder-muted-foreground focus:outline-none focus:border-primary-500/50"
          />
        </div>
        {projects.length > 0 && (
          <select
            value={projectFilter}
            onChange={(e) => { setProjectFilter(e.target.value); setVulnsPage(0); }}
            className="bg-card border border-border rounded px-2 py-1.5 text-[13px] text-foreground/90 font-mono focus:outline-none focus:border-primary-500/50"
          >
            <option value="all">All projects</option>
            {projects.map((p) => (
              <option key={p.token} value={p.token}>
                {p.client} — {p.name}
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center text-muted-foreground/80 bg-card/40 rounded-lg border border-border/40 border-dashed">
          <ShieldAlert className="w-8 h-8 mx-auto mb-3 opacity-20" />
          <p className="text-sm font-mono">No vulnerabilities match</p>
        </div>
      ) : (
        <div className="bg-card rounded-lg border border-border overflow-hidden">
          <table className="w-full text-left">
            <thead className="border-b border-border">
              <tr className="text-[13px] text-muted-foreground font-mono">
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Finding</th>
                <th className="px-4 py-2.5 font-medium w-28">Severity</th>
                <th className="px-4 py-2.5 font-medium">Path / URL</th>
                <th className="px-4 py-2.5 font-medium w-16"></th>
              </tr>
            </thead>
            <tbody>
              {pagedVulns.map((vuln, idx) => {
                const key = `${(vuln as any).targetId}:${vuln.id}:${vuln.path}:${vulnsPage * VULNS_PAGE_SIZE + idx}`;
                const expanded = expandedKeys.has(key);
                const rawContent = (vuln as any).rawContent as
                  | string
                  | undefined;
                return (
                  <React.Fragment key={key}>
                    <tr className="border-b border-border/50 hover:bg-secondary/20 transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-foreground/80">
                        <Link
                          to={`/targets/${(vuln as any).targetId}`}
                          className="hover:text-primary-400 transition-colors"
                        >
                          {(vuln as any).targetDomain}
                        </Link>
                      </td>
                      <td className="px-4 py-3 text-sm text-foreground max-w-xs">
                        <div className="font-medium truncate" title={vuln.name}>
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(vuln.name) }} />
                        </div>
                        {vuln.description && (
                          <div
                            className="text-xs text-muted-foreground font-mono mt-0.5 truncate"
                            title={vuln.description}
                          >
                            <span dangerouslySetInnerHTML={{ __html: ansiToHtml(vuln.description) }} />
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
                      <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-xs">
                        <div className="truncate" title={vuln.path}>
                          {vuln.path ? <span dangerouslySetInnerHTML={{ __html: ansiToHtml(vuln.path) }} /> : "—"}
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
                            className="p-1 text-muted-foreground/80 hover:text-foreground/80 transition-colors"
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
                                  : "text-muted-foreground/80 hover:text-foreground/80"
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
                      <tr className="border-b border-border/50 bg-background/60">
                        <td colSpan={5} className="px-4 py-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-[13px] text-muted-foreground font-mono">
                              Raw output
                            </span>
                            <button
                              onClick={() =>
                                navigator.clipboard.writeText(rawContent)
                              }
                              className="text-[13px] text-muted-foreground hover:text-primary-400 transition-colors font-mono flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" /> Copy raw
                            </button>
                          </div>
                          <pre
                            className="text-xs text-foreground/80 font-mono whitespace-pre-wrap leading-relaxed bg-background rounded border border-border p-3 overflow-x-auto max-h-96"
                            dangerouslySetInnerHTML={{ __html: ansiToHtml(rawContent) }}
                          />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
          {totalVulnsPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-muted/20 text-xs text-muted-foreground font-mono">
              <span>{filtered.length} findings — page {vulnsPage + 1} of {totalVulnsPages}</span>
              <div className="flex gap-1">
                <button
                  disabled={vulnsPage === 0}
                  onClick={() => setVulnsPage(0)}
                  className="px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-30"
                >«</button>
                <button
                  disabled={vulnsPage === 0}
                  onClick={() => setVulnsPage((p) => p - 1)}
                  className="px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-30"
                >‹</button>
                <button
                  disabled={vulnsPage >= totalVulnsPages - 1}
                  onClick={() => setVulnsPage((p) => p + 1)}
                  className="px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-30"
                >›</button>
                <button
                  disabled={vulnsPage >= totalVulnsPages - 1}
                  onClick={() => setVulnsPage(totalVulnsPages - 1)}
                  className="px-2 py-1 rounded border border-border hover:bg-muted disabled:opacity-30"
                >»</button>
              </div>
            </div>
          )}
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
      <div className="flex gap-0 border-b border-border">
        <button
          onClick={() => setActiveTab("launcher")}
          className={`px-4 py-2.5 text-xs font-mono border-b-2 transition-colors ${
            activeTab === "launcher"
              ? "border-primary-500 text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground/80"
          }`}
        >
          Launch Scan
        </button>
        <button
          onClick={() => setActiveTab("active")}
          className={`px-4 py-2.5 text-xs font-mono border-b-2 transition-colors ${
            activeTab === "active"
              ? "border-primary-500 text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground/80"
          }`}
        >
          Active Scans
        </button>
        <button
          onClick={() => setActiveTab("output")}
          className={`px-4 py-2.5 text-xs font-mono border-b-2 transition-colors ${
            activeTab === "output"
              ? "border-primary-500 text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground/80"
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
        <span className="text-sm font-semibold text-foreground/80 font-mono">
          Fleet
          {hiddenCount > 0 && (
            <button
              onClick={() => setHiddenIds(new Set())}
              className="ml-3 text-[13px] text-muted-foreground hover:text-foreground/80 font-mono transition-colors"
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
            className="bg-card text-foreground/90 border border-border px-3 py-1.5 rounded-lg text-[13px] font-mono focus:outline-none focus:border-primary-500 transition-colors"
          >
            <option value="managed">AX managed</option>
            <option value="all">All instances</option>
            <option value="prefix">By name prefix…</option>
          </select>
          {filterMode === "prefix" && (
            <input
              type="text"
              value={customPrefix}
              onChange={(e) => setCustomPrefix(e.target.value)}
              placeholder="e.g. dns01"
              className="bg-card text-foreground border border-border px-3 py-1.5 rounded-lg text-[13px] font-mono w-32 focus:outline-none focus:border-primary-500 transition-colors placeholder:text-muted-foreground/80"
            />
          )}
          <button
            onClick={() => loadFleet(true)}
            disabled={loading}
            className="bg-secondary hover:bg-accent disabled:opacity-50 text-foreground/80 hover:text-foreground border border-border px-3 py-1.5 rounded-lg text-[13px] font-mono transition-colors"
          >
            {loading ? "Refreshing…" : "↺ Refresh"}
          </button>
        </div>
      </div>
      {loading && fleet.length === 0 ? (
        <div className="text-center text-muted-foreground py-20 font-mono text-[13px]">
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
    { id: "themes", label: "Themes" },
    { id: "importing", label: "Importing Results" },
    { id: "fleet", label: "Fleet Management" },
    { id: "notifications", label: "Notifications" },
    { id: "workflow", label: "Workflow Builder" },
    { id: "triage", label: "Findings Triage" },
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
    {
      name: "searchsploit",
      type: "Exploits",
      fmt: "JSONL",
      desc: "Offline Exploit-DB search. Also queryable directly from Findings Triage (local, no fleet needed).",
    },
    {
      name: "metasploit",
      type: "Exploits",
      fmt: "TXT",
      desc: "Runs an msfconsole auxiliary module against targets (default: HTTP version scan) — customize the resource script for other modules.",
    },
  ];
  const C = ({ v }: { v: string }) => (
    <code className="bg-background border border-border rounded px-1.5 py-0.5 text-cyan-400 text-xs font-mono">
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
      <div className="border-b border-border pb-3">
        <h2 className="text-xl font-bold text-foreground">{title}</h2>
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
      className={`bg-card rounded-lg border border-border p-4 ${className}`}
    >
      {children}
    </div>
  );
  return (
    <div className="flex gap-6 animate-fade-in">
      <div className="w-44 flex-shrink-0">
        <div className="bg-card rounded-lg border border-border p-2 sticky top-6">
          <p className="text-[13px] text-muted-foreground/80 font-mono mb-2 px-2">
            Contents
          </p>
          {sections.map((s) => (
            <button
              key={s.id}
              onClick={() => setActiveSection(s.id)}
              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors mb-0.5 ${
                activeSection === s.id
                  ? "bg-primary-500/20 text-primary-300 font-medium"
                  : "text-foreground/80 hover:bg-secondary hover:text-foreground"
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
            <p className="text-foreground/80 text-sm leading-relaxed">
              GUI-AX connects to the{" "}
              <span className="text-foreground font-semibold">axiom-bridge</span> Python
              server, which drives the Ax framework and your cloud fleet.
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
                  <div className="text-foreground font-semibold text-sm">{t}</div>
                  <div className="text-muted-foreground text-sm mt-0.5">{d}</div>
                </div>
              </div>
            ))}
          </Card>
          <Card>
            <h3 className="text-foreground font-semibold mb-3">
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
                  className="flex items-start gap-3 py-1.5 border-b border-border/50 font-mono text-xs"
                >
                  <span className="text-cyan-400 w-36 flex-shrink-0">{k}</span>
                  <span className="text-primary-300 flex-shrink-0">{v}</span>
                  <span className="text-muted-foreground">{d}</span>
                </div>
              ))}
            </div>
          </Card>
        </Sec>
        <Sec id="modules" title="Scan Modules">
          <div className="bg-card rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-background/60 border-b border-border">
                <tr className="text-[13px] text-muted-foreground font-mono">
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
                    className={`border-b border-border/50 ${i % 2 ? "bg-background/20" : ""}`}
                  >
                    <td className="px-4 py-3 font-mono text-cyan-400 font-semibold">
                      {m.name}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-[14px] font-semibold bg-primary-500/15 text-primary-300 border border-primary-500/30 px-2 py-0.5 rounded font-mono">
                        {m.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground font-mono text-xs">
                      {m.fmt}
                    </td>
                    <td className="px-4 py-3 text-foreground/80 text-xs">
                      {m.desc}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Card>
            <h3 className="text-foreground font-semibold mb-2">
              Module availability
            </h3>
            <p className="text-foreground/80 text-sm">
              The Scan Launcher only shows modules whose binary is installed and
              in PATH on the bridge server. If a module doesn’t appear, install
              the tool in the AX image or on the bridge host.
            </p>
          </Card>
        </Sec>
        <Sec id="dashboard" title="Dashboard Guide">
          <div className="space-y-3">
            {[
              [
                "Dashboard",
                "Stat cards, geo map, port chart, and the most recent scan results. Cards deep-link into the matching page (e.g. Vulnerabilities). If a project is active, the dashboard is scoped to it.",
              ],
              [
                "Projects",
                "Organise work into projects and set one as your active project. The Dashboard, Vulnerabilities, Findings Triage, and CVE Inventory pages then default their project filter to it. Scans labelled gw-<client>-… link to a project automatically.",
              ],
              [
                "Targets",
                "All imported results create target entries. Click a target to see subdomains, ports, vulns, websites, and a topology graph. The default tab matches the scan type.",
              ],
              [
                "Vulnerabilities",
                "Every finding across targets in one list. Filter by severity, search, and project, then Export the filtered list as JSON, CSV, or TXT.",
              ],
              [
                "Findings Triage",
                "Review queue with severity/target/project filters, false-positive marking, CVE + SearchSploit enrichment on expand, and CSV export.",
              ],
              [
                "CVE Inventory",
                "Matches discovered technologies/versions to NVD CVEs, enriched from CVEProject/cvelistV5 with KEV (actively exploited) and PoC badges. A legend explains every badge.",
              ],
              [
                "Scans → Quick Scan",
                "Single-target form: enter a target, tick a few modules (httpx/nuclei/…), and launch one scan per module against a fresh fleet.",
              ],
              [
                "Scans → Launch",
                "Full builder: select a module, enter targets (one per line), name the scan, and click Launch. Output is auto-generated as module+timestamp.ext.",
              ],
              [
                "Scans → Active/Monitor",
                "Running scans with elapsed time and cancel button. History table sorted newest-first.",
              ],
              [
                "Workflows",
                "Chain modules into a DAG pipeline (sequential, parallel, and fan-in steps), save custom templates, and watch per-step progress live.",
              ],
              [
                "Fleet",
                "Ax-managed instances. Use checkboxes for bulk power-off or terminate (requires confirmation), or run a command across the fleet.",
              ],
              ["Settings", "Bridge URL, theme (light/dark), MCP server toggle, Ax framework updater, AI provider preference, geo map privacy (online IP lookups on/off), and standalone project management."],
            ].map(([t, d]) => (
              <div key={t}>
                <Card>
                  <h3 className="text-foreground font-semibold text-sm mb-1">{t}</h3>
                  <p className="text-foreground/80 text-sm">{d}</p>
                </Card>
              </div>
            ))}
          </div>
        </Sec>
        <Sec id="themes" title="Themes">
          <div className="space-y-3">
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Switching themes
              </h3>
              <p className="text-foreground/80 text-sm">
                Click the{" "}
                <span className="text-foreground font-medium">
                  sun / moon
                </span>{" "}
                icon in the top-right bar to toggle between light and dark mode.
                The choice is saved in <C v="localStorage" /> and restored on
                next visit.
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Light mode — editorial
              </h3>
              <p className="text-foreground/80 text-sm mb-3">
                White canvas with solid, fully-opaque coloured stat tiles. Each
                tile has a deep-tint border-top matching its accent colour. The
                sidebar is white with a soft drop shadow and three section
                labels in distinct tones:
              </p>
              <ul className="space-y-1.5 text-sm text-foreground/80">
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-orange-600 flex-shrink-0" />
                  Targets — burnt-orange
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-teal-700 flex-shrink-0" />
                  Operations — deep teal
                </li>
                <li className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-amber-600 flex-shrink-0" />
                  System — amber
                </li>
              </ul>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Dark mode — Raycast
              </h3>
              <p className="text-foreground/80 text-sm">
                Near-black canvas (<C v="#07080a" />) with hairline 1 px
                borders and a surface ladder. Stat tiles show their accent
                colour as a top border only; hovering reveals a matching
                coloured glow behind the card. The geo map switches to a dark
                ocean-blue palette.
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Transition animation
              </h3>
              <p className="text-foreground/80 text-sm">
                Toggling the theme triggers a 1-second cross-fade for all
                colours and a staggered bounce-pop on the stat tiles — each
                card springs up then settles, offset by 55 ms per tile so they
                cascade rather than all move at once.
              </p>
            </Card>
          </div>
        </Sec>
        <Sec id="importing" title="Importing Results">
          <Card className="space-y-4">
            <p className="text-foreground/80 text-sm">
              Drop any scan output file into <C v="imports/" />. A polling thread
              (every <C v="WATCHER_INTERVAL" /> seconds, default 300) detects the
              scanner type from the filename prefix and imports it. No
              subdirectories needed — or trigger it immediately with the reimport
              action.
            </p>
            <div>
              <h3 className="text-foreground font-semibold text-sm mb-3">
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
                    <span className="text-muted-foreground">→</span>
                    <span className="text-foreground/80">{d}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h3 className="text-foreground font-semibold text-sm mb-2">
                Import lifecycle
              </h3>
              <ol className="space-y-1 text-sm text-foreground/80">
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
              <h3 className="text-foreground font-semibold mb-2">
                Instance selection
              </h3>
              <p className="text-foreground/80 text-sm">
                Fleet shows AX-managed instances from{" "}
                <C v="~/.axiom/selected.conf" />. Use the filter dropdown for
                all vs managed. Row checkboxes enable bulk{" "}
                <span className="text-foreground font-medium">Power Off</span> /
                <span className="text-danger-400 font-medium"> Terminate</span>{" "}
                actions.
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">Fleet cache</h3>
              <p className="text-foreground/80 text-sm">
                Fleet data is cached for{" "}
                <span className="text-foreground font-medium">30 s</span> (env{" "}
                <C v="FLEET_CACHE_TTL" />) to avoid hammering the cloud API.
                Click <span className="text-foreground font-medium">↺ Refresh</span>{" "}
                to force a fresh query.
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">Safety</h3>
              <ul className="space-y-1.5 text-sm text-foreground/80">
                <li>
                  • All{" "}
                  <span className="text-danger-400 font-medium">Terminate</span>{" "}
                  actions require a confirmation dialog
                </li>
                <li>• Bulk terminate shows instance count before confirming</li>
                <li>• Power off is reversible; terminate is permanent</li>
                <li>• Only AX-managed instances shown by default</li>
              </ul>
            </Card>
          </div>
        </Sec>
        <Sec id="notifications" title="Notifications">
          <div className="space-y-3">
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                In-app notifications
              </h3>
              <p className="text-foreground/80 text-sm mb-3">
                The bell icon shows unread count. Click it to open the panel.
                Toast notifications auto-dismiss after 5 s.
              </p>
              <ul className="space-y-1.5 text-sm text-foreground/80">
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
              <h3 className="text-foreground font-semibold mb-2">
                Browser notifications
              </h3>
              <p className="text-foreground/80 text-sm">
                When you grant browser notification permission, native OS
                notifications are sent when scans complete or fleet actions
                finish — useful when the dashboard is in a background tab.
                Permission is requested automatically the first time a
                notification fires.
              </p>
            </Card>
          </div>
        </Sec>
        <Sec id="workflow" title="Workflow Builder">
          <div className="space-y-3">
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Overview
              </h3>
              <p className="text-foreground/80 text-sm">
                Chain multiple scan modules into a pipeline. Each step's output
                feeds automatically as input to the next —{" "}
                <C v="amass" /> subdomains pipe into <C v="httpx" />, which
                feeds <C v="nuclei" />, and so on. Steps can run sequentially,
                in parallel (siblings), or converge (fan-in). Currently in{" "}
                <span className="text-warn-400 font-mono text-xs font-semibold bg-warn-400/10 border border-warn-400/30 px-1.5 py-0.5 rounded">
                  BETA
                </span>
                .
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">Build tab</h3>
              <ul className="space-y-1.5 text-sm text-foreground/80">
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Input type
                  </span>{" "}
                  — domains, subdomains, IPs, URLs, or mixed (auto-detected
                  from your paste)
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">Targets</span>{" "}
                  — one per line
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">Templates</span>{" "}
                  — built-in quick-start pipelines for common recon flows; save
                  your own as custom templates (persisted in localStorage)
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Module picker
                  </span>{" "}
                  — 36 modules across 9 categories: OSINT, enum, DNS, port,
                  HTTP, vuln, screenshot, fuzz, URL, tech
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Step editor
                  </span>{" "}
                  — custom arguments and fleet instance count (min / max) per
                  step; enable or disable individual steps without removing
                  them
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Auto-terminate
                  </span>{" "}
                  — destroy fleet instances automatically when the workflow
                  finishes
                </li>
              </ul>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">Run tab</h3>
              <p className="text-foreground/80 text-sm">
                Live execution view. Displays workflow status (
                <span className="text-success-400 font-medium">running</span> /{" "}
                <span className="text-success-400 font-medium">completed</span>{" "}
                /{" "}
                <span className="text-danger-400 font-medium">failed</span> /{" "}
                <span className="text-muted-foreground font-medium">
                  aborted
                </span>
                ), target count, elapsed time, and a live step-tree showing
                per-step progress. Click{" "}
                <span className="text-foreground font-medium">Abort</span> to
                stop mid-flight.
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                History tab
              </h3>
              <p className="text-foreground/80 text-sm">
                All past runs sorted newest-first. Each entry shows the
                workflow name, final status, module count, and timestamp.
              </p>
            </Card>
          </div>
        </Sec>
        <Sec id="triage" title="Findings Triage">
          <div className="space-y-3">
            <Card>
              <h3 className="text-foreground font-semibold mb-2">Overview</h3>
              <p className="text-foreground/80 text-sm">
                Consolidated review queue of every vulnerability and security
                finding across all targets. Aggregates <C v="nuclei" /> output,
                CVE enrichment, and exploit references in one place. The stats
                bar at the top shows counts by severity and total false
                positives.
              </p>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">Filters</h3>
              <ul className="space-y-1.5 text-sm text-foreground/80">
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">Search</span>{" "}
                  — debounced full-text search across finding name, path, and
                  matched content
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">Severity</span>{" "}
                  — filter to{" "}
                  <span className="text-danger-400">CRITICAL</span> /{" "}
                  <span className="text-orange-400">HIGH</span> /{" "}
                  <span className="text-warn-400">MEDIUM</span> /{" "}
                  <span className="text-success-400">LOW</span> /{" "}
                  <span className="text-cyan-400">INFO</span>
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">Target</span>{" "}
                  — limit to a single domain
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">Show FPs</span>{" "}
                  — toggle visibility of false-positive-marked findings
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Unique only
                  </span>{" "}
                  — hide duplicates; show each finding once regardless of how
                  many targets it appeared on
                </li>
              </ul>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Expanded row
              </h3>
              <p className="text-foreground/80 text-sm mb-2">
                Click any row to expand it and see:
              </p>
              <ul className="space-y-1.5 text-sm text-foreground/80">
                <li>• Full description and raw matched content</li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">CVE panel</span>{" "}
                  — CVSS v3 score (colour-coded), vector string, and up to 3
                  NVD references (auto-fetched when a CVE ID is detected in the
                  finding)
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    SearchSploit
                  </span>{" "}
                  — queries the local Exploit-DB for matching exploit modules
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">HackTricks</span>{" "}
                  — direct link for technique background reading
                </li>
              </ul>
            </Card>
            <Card>
              <h3 className="text-foreground font-semibold mb-2">
                Triage actions
              </h3>
              <ul className="space-y-1.5 text-sm text-foreground/80">
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Mark as FP
                  </span>{" "}
                  — the FP button on each row flags a finding as a false
                  positive. It dims to 40% opacity and can be hidden with the
                  Show FPs toggle. The flag is persisted via the bridge API
                  and survives page refreshes.
                </li>
                <li>
                  •{" "}
                  <span className="text-foreground font-medium">
                    Export CSV
                  </span>{" "}
                  — downloads all currently-visible findings (active filters
                  apply) as a <C v=".csv" /> with columns: ID, Name, Severity,
                  Target, Path, Matched, CVE, False Positive, Duplicate.
                  Filename includes today's date.
                </li>
              </ul>
            </Card>
          </div>
        </Sec>
      </div>
    </div>
  );
};

// ───────────── Main App ─────────────

const App = ({
  onLogout,
  username,
  role,
}: {
  onLogout?: () => void;
  username?: string | null;
  role?: string | null;
}) => {
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
    <div className="min-h-screen bg-background text-foreground font-sans selection:bg-primary/30">
      <Sidebar role={role} />
      <Header
        unreadCount={unreadCount}
        onBellClick={() => setShowNotifPanel((v) => !v)}
        onLogout={onLogout}
        username={username}
      />
      <main className="ml-56">
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
              path="/projects"
              element={
                <ProjectsPage
                  apiUrl="http://localhost:5000"
                  username={username ?? null}
                />
              }
            />
            <Route
              path="/quickscan"
              element={<QuickScanPage apiUrl="http://localhost:5000" />}
            />
            <Route
              path="/scans"
              element={<ScansPage onTargetsRefresh={loadTargets} />}
            />
            <Route
              path="/fleet"
              element={<FleetControlPage onNotify={addNotification} />}
            />
            <Route
              path="/workflow"
              element={<WorkflowBuilder apiUrl="http://localhost:5000" username={username} />}
            />
            <Route path="/settings" element={<Settings />} />
            <Route path="/docs" element={<DocsPage />} />
            <Route path="/vulns" element={<VulnsPage targets={targets} />} />
            <Route path="/triage" element={<FindingsTriage />} />
            <Route path="/inventory" element={<InventoryMonitor />} />
            <Route path="/wordlists" element={<WordlistManager />} />
            <Route path="/profile" element={<UserProfile />} />
            <Route
              path="/admin"
              element={
                role === null || role === "admin" ? (
                  <AdminPanel />
                ) : (
                  <div className="text-center mt-20 text-muted-foreground font-mono text-sm">
                    Access denied.
                  </div>
                )
              }
            />
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
                  <div className="text-center mt-20 text-muted-foreground">
                    Loading Target...
                  </div>
                )
              }
            />
            <Route
              path="*"
              element={
                <div className="text-center mt-20 text-muted-foreground">
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
            className="bg-card border border-border rounded-lg p-3 flex items-start gap-3 pointer-events-auto min-w-[260px] max-w-[340px] animate-fade-in"
          >
            <div
              className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${notifDotColor(n.type)}`}
            />
            <div className="flex-1 min-w-0">
              <div className="text-foreground text-sm font-semibold">{n.title}</div>
              <div className="text-muted-foreground text-xs mt-0.5">{n.message}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Notification Panel */}
      {showNotifPanel && (
        <div className="fixed top-12 right-0 z-[150] w-72 bg-card border border-border rounded-b-lg shadow-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <span className="text-sm font-semibold text-foreground">
              Notifications
            </span>
            <div className="flex items-center gap-3">
              <button
                onClick={markAllRead}
                className="text-[13px] text-muted-foreground hover:text-foreground transition-colors"
              >
                Mark all read
              </button>
              <button
                onClick={() => setShowNotifPanel(false)}
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <X size={14} />
              </button>
            </div>
          </div>
          <div className="max-h-[420px] overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="text-center py-10 text-muted-foreground text-sm font-mono">
                No notifications yet
              </div>
            ) : (
              notifications.slice(0, 20).map((n) => (
                <div
                  key={n.id}
                  className={`px-4 py-3 border-b border-border/50 hover:bg-secondary/30 transition-colors ${
                    n.read ? "opacity-50" : ""
                  }`}
                >
                  <div className="flex items-start gap-2.5">
                    <div
                      className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${n.read ? "bg-accent" : notifDotColor(n.type)}`}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-foreground font-medium">
                        {n.title}
                      </div>
                      <div className="text-xs text-muted-foreground mt-0.5">
                        {n.message}
                      </div>
                      <div className="text-[13px] text-muted-foreground/80 mt-1 font-mono">
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
  const [myTeams, setMyTeams] = useState<ProjectTeam[]>([]);
  const [teamView, setTeamView] = useState<string>("all");
  const [myProjects, setMyProjects] = useState<AxProject[]>([]);
  const [activeProjectToken, setActiveProjectToken] = useState<string | null>(null);
  const [projectView, setProjectView] = useState<string>("all");
  const [newCveStats, setNewCveStats] = useState<{
    totalCves: number; newCves: number;
    critical: number; high: number; medium: number; low: number;
    newCritical: number; newHigh: number;
    lastScan: string | null;
  }>({ totalCves: 0, newCves: 0, critical: 0, high: 0, medium: 0, low: 0, newCritical: 0, newHigh: 0, lastScan: null });

  // Load teams the current user belongs to
  useEffect(() => {
    const loadTeams = async () => {
      try {
        const [meRes, teamsRes] = await Promise.all([
          fetch("http://localhost:5000/api/users/me", {
            credentials: "include",
          }),
          fetch("http://localhost:5000/api/teams", { credentials: "include" }),
        ]);
        if (meRes.ok && teamsRes.ok) {
          const me = await meRes.json();
          const all: ProjectTeam[] = await teamsRes.json();
          // Sort newest team first
          const sorted = all
            .filter((t) => me.teams?.includes(t.id))
            .sort(
              (a, b) =>
                new Date(b.createdAt).getTime() -
                new Date(a.createdAt).getTime(),
            );
          setMyTeams(sorted);
        }
      } catch {
        // bridge may not support teams yet — keep empty
      }
    };
    loadTeams();
  }, []);

  // Load projects and active project preference
  useEffect(() => {
    const loadProjects = async () => {
      try {
        const [projRes, prefsRes] = await Promise.all([
          fetch("http://localhost:5000/api/projects/mine", { credentials: "include" }),
          fetch("http://localhost:5000/api/users/me/prefs", { credentials: "include" }),
        ]);
        if (projRes.ok) {
          const data = await projRes.json();
          const list: AxProject[] = Array.isArray(data) ? data : Object.values(data);
          setMyProjects(list);
        }
        if (prefsRes.ok) {
          const prefs = await prefsRes.json();
          if (prefs.active_project) {
            setActiveProjectToken(prefs.active_project);
            setProjectView(prefs.active_project);
          }
        }
      } catch {
        // bridge offline — ignore
      }
    };
    loadProjects();
  }, []);

  // Fetch CVE stats for the dashboard card, respecting the project filter
  useEffect(() => {
    const loadCveStats = async () => {
      try {
        let url = "http://localhost:5000/api/inventory";
        if (projectView !== "all") {
          url += `?projectToken=${encodeURIComponent(projectView)}`;
        }
        const r = await fetch(url, { credentials: "include" });
        if (!r.ok) return;
        const inv = await r.json();
        type CveEntry = { severity: string; is_new?: boolean };
        const allCves: CveEntry[] = (inv.technologies || []).flatMap(
          (t: { cves: CveEntry[] }) => t.cves
        );
        const isNew = (c: CveEntry) => c.is_new === true;
        setNewCveStats({
          totalCves:   allCves.length,
          newCves:     allCves.filter(isNew).length,
          critical:    allCves.filter((c) => c.severity === "CRITICAL").length,
          high:        allCves.filter((c) => c.severity === "HIGH").length,
          medium:      allCves.filter((c) => c.severity === "MEDIUM").length,
          low:         allCves.filter((c) => c.severity === "LOW").length,
          newCritical: allCves.filter((c) => isNew(c) && c.severity === "CRITICAL").length,
          newHigh:     allCves.filter((c) => isNew(c) && c.severity === "HIGH").length,
          lastScan:    inv.last_full_scan ?? null,
        });
      } catch {
        // inventory not available yet — leave defaults
      }
    };
    loadCveStats();
  }, [projectView, myProjects]);

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

  // Compute filtered targets based on selected team/user view
  const teamFilteredTargets = useMemo(() => {
    if (teamView === "all" || myTeams.length === 0) return targets;
    if (teamView === "personal") {
      // Exclude anything that matches any team prefix (direct scans: teamSlug/
      // or workflow scans: wf-teamSlug-)
      const slugs = myTeams.map((t) => toTeamSlug(t.name));
      return targets.filter(
        (t) =>
          !slugs.some(
            (slug) =>
              t.id?.toLowerCase().startsWith(slug + "/") ||
              t.programName?.toLowerCase().startsWith(slug + "/") ||
              t.id?.toLowerCase().startsWith("wf-" + slug + "-") ||
              t.programName?.toLowerCase().startsWith("wf-" + slug + "-"),
          ),
      );
    }
    if (teamView.startsWith("team:")) {
      const teamId = teamView.slice(5);
      const team = myTeams.find((t) => t.id === teamId);
      if (!team) return targets;
      const slug = toTeamSlug(team.name);
      // Match direct scans (teamSlug/...) and workflow scans (wf-teamSlug-...)
      return targets.filter(
        (t) =>
          t.id?.toLowerCase().startsWith(slug + "/") ||
          t.programName?.toLowerCase().startsWith(slug + "/") ||
          t.id?.toLowerCase().startsWith("wf-" + slug + "-") ||
          t.programName?.toLowerCase().startsWith("wf-" + slug + "-"),
      );
    }
    return targets;
  }, [targets, teamView, myTeams]);

  // Project-filtered targets fetched server-side via projectToken.
  // Cleared to [] immediately on project change so GeoMap / metrics never
  // show all-targets data while the fetch is in-flight.
  const [projectTargets, setProjectTargets] = useState<Target[] | null>(null);
  useEffect(() => {
    if (projectView === "all") {
      setProjectTargets(null);
      return;
    }
    setProjectTargets([]); // clear immediately — hides stale data during fetch
    fetch(`http://localhost:5000/api/targets?projectToken=${encodeURIComponent(projectView)}`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then((data) => setProjectTargets(Array.isArray(data) ? data : []))
      .catch(() => setProjectTargets([]));
  }, [projectView]);

  // Further filter by selected project — use server-side result when available
  const filteredTargets = projectView !== "all" && projectTargets !== null
    ? projectTargets
    : teamFilteredTargets;

  // Enhanced dashboard metrics
  const metrics = getDashboardMetrics(filteredTargets, fleet);

  return (
    <div className="space-y-3 animate-fade-in">
      {/* Page header */}
      <div className="relative flex items-center justify-between pb-0">
        <div className="flex items-center gap-4">
          <div>
            <h1 className="text-base font-bold text-foreground tracking-tight">
              Overview
            </h1>
            <p className="text-[11px] text-muted-foreground font-mono mt-0.5">
              Intelligence dashboard
            </p>
          </div>
          {/* Team / user filter dropdown */}
          <select
            value={teamView}
            onChange={(e) => setTeamView(e.target.value)}
            className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-muted-foreground font-mono focus:outline-none focus:border-primary-500/40 cursor-pointer transition-colors hover:border-border"
          >
            <option value="all">All</option>
            <option value="personal">Personal (no team)</option>
            {myTeams.map((t) => (
              <option key={t.id} value={`team:${t.id}`}>
                {t.name}
              </option>
            ))}
          </select>

          {/* Project filter dropdown */}
          {myProjects.length > 0 && (
            <select
              value={projectView}
              onChange={(e) => setProjectView(e.target.value)}
              className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-muted-foreground font-mono focus:outline-none focus:border-primary-500/40 cursor-pointer transition-colors hover:border-border"
              title="Filter by project"
            >
              <option value="all">All projects</option>
              {/* Active project first */}
              {activeProjectToken && myProjects.find((p) => p.token === activeProjectToken) && (
                <option value={activeProjectToken}>
                  ★ {myProjects.find((p) => p.token === activeProjectToken)!.client} (active)
                </option>
              )}
              {/* Remaining projects alphabetically */}
              {myProjects
                .filter((p) => p.token !== activeProjectToken)
                .sort((a, b) => a.client.localeCompare(b.client))
                .map((p) => (
                  <option key={p.token} value={p.token}>
                    {p.client} — {p.name}
                  </option>
                ))}
            </select>
          )}
        </div>
        {/* Decorative scope / crosshair art */}
        <div
          className="absolute right-20 -top-3 opacity-[0.07] pointer-events-none"
          aria-hidden="true"
        >
          <svg
            width="90"
            height="90"
            viewBox="0 0 100 100"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <circle
              cx="50"
              cy="50"
              r="48"
              stroke="#8b5cf6"
              strokeWidth="0.8"
              strokeDasharray="6 4"
            />
            <circle cx="50" cy="50" r="35" stroke="#8b5cf6" strokeWidth="0.8" />
            <circle cx="50" cy="50" r="20" stroke="#06b6d4" strokeWidth="0.8" />
            <circle cx="50" cy="50" r="4" fill="#8b5cf6" opacity="0.6" />
            <line
              x1="50"
              y1="2"
              x2="50"
              y2="30"
              stroke="#8b5cf6"
              strokeWidth="0.8"
            />
            <line
              x1="50"
              y1="70"
              x2="50"
              y2="98"
              stroke="#8b5cf6"
              strokeWidth="0.8"
            />
            <line
              x1="2"
              y1="50"
              x2="30"
              y2="50"
              stroke="#8b5cf6"
              strokeWidth="0.8"
            />
            <line
              x1="70"
              y1="50"
              x2="98"
              y2="50"
              stroke="#8b5cf6"
              strokeWidth="0.8"
            />
          </svg>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="text-xs text-muted-foreground hover:text-foreground/70 font-mono transition-colors disabled:opacity-40"
        >
          {loading ? "Syncing..." : "Refresh"}
        </button>
      </div>

      {/* Stat Cards Row 1 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Scans"
          value={metrics.totalTargets}
          icon={TargetIcon}
          accentClass="stat-accent-target"
          iconBg="bg-primary-500/12"
          iconColor="text-primary-400"
          onClick={() => navigate("/targets")}
        />
        <StatCard
          title="Subdomains"
          value={metrics.totalSubdomains}
          icon={Globe}
          accentClass="stat-accent-sub"
          iconBg="bg-cyan-500/12"
          iconColor="text-cyan-400"
          onClick={() => navigate("/targets")}
        />
        <StatCard
          title="Open Ports"
          value={metrics.totalPorts}
          icon={Server}
          accentClass="stat-accent-port"
          iconBg="bg-blue-500/12"
          iconColor="text-blue-400"
          onClick={() => navigate("/targets")}
        />
        <StatCard
          title="Vulnerabilities"
          value={metrics.totalVulns}
          icon={ShieldAlert}
          accentClass="stat-accent-vuln"
          iconBg="bg-danger-500/12"
          iconColor="text-danger-400"
          onClick={() => navigate("/vulns")}
        />
      </div>

      {/* Stat Cards Row 2 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Critical / High"
          value={metrics.highCriticalVulns}
          icon={ShieldAlert}
          accentClass="stat-accent-critical"
          iconBg="bg-orange-500/12"
          iconColor="text-orange-400"
          onClick={() => navigate("/vulns?sev=CRITICAL")}
        />
        <StatCard
          title="Active Scans"
          value={runningScansCount}
          icon={Activity}
          accentClass="stat-accent-scan"
          iconBg="bg-success-500/12"
          iconColor="text-success-400"
          onClick={() => navigate("/scans")}
        />
        <StatCard
          title="Fleet Nodes"
          value={`${metrics.fleetActive} / ${metrics.fleetTotal}`}
          icon={Server}
          accentClass="stat-accent-fleet"
          iconBg="bg-primary-400/12"
          iconColor="text-primary-300"
          onClick={() => navigate("/fleet")}
        />
        <div
          onClick={() => navigate("/targets")}
          className="relative rounded-xl bg-card border border-border stat-accent-amber tile-hover cursor-pointer"
        >
          <div className="tile-shine" />
          <div className="p-4">
            <div className="flex items-start justify-between mb-3">
              <div className="h-9 w-9 rounded-lg flex items-center justify-center bg-success-500/12">
                <Activity className="w-[18px] h-[18px] text-success-400" />
              </div>
            </div>
            <div className="text-2xl font-bold text-foreground tabular-nums tracking-tight leading-none mb-1">
              {filteredTargets.length > 0
                ? Math.round(
                    (filteredTargets.filter((t) => t.status === "COMPLETED")
                      .length /
                      filteredTargets.length) *
                      100,
                  )
                : 0}
              %
            </div>
            <div className="text-[11px] text-muted-foreground font-mono uppercase tracking-wider mb-3">
              Scan Success
            </div>
            <div className="w-full bg-secondary/50 rounded-full h-[2px] overflow-hidden">
              <div
                className="bg-success-500 h-full rounded-full transition-all risk-bar-fill"
                style={{
                  width: `${filteredTargets.length > 0 ? (filteredTargets.filter((t) => t.status === "COMPLETED").length / filteredTargets.length) * 100 : 0}%`,
                }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Middle row: Ports chart + Assets + Fleet Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Most Common Ports */}
        <div className="bg-card rounded-xl border border-border p-4 tile-hover">
          <div className="tile-shine" />
          <div className="flex items-center justify-between mb-4">
            <h3 className="panel-title">Top Open Ports</h3>
            <button
              onClick={() => navigate("/targets")}
              className="text-xs text-muted-foreground hover:text-foreground/80 font-mono transition-colors"
            >
              View all →
            </button>
          </div>
          {(() => {
            const commonPorts = getCommonPorts(filteredTargets);
            const top5 = commonPorts.slice(0, 5);
            const maxCount = top5[0]?.count || 1;
            return commonPorts.length === 0 ? (
              <p className="text-muted-foreground text-xs text-[13px] text-center py-8 font-mono">
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
                      <span className="font-mono text-[13px] text-foreground/90 w-10 flex-shrink-0">
                        {entry.port}
                      </span>
                      <div className="flex-1 bg-secondary rounded-full h-1 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${(entry.count / maxCount) * 100}%`,
                            backgroundColor:
                              pieColors[index % pieColors.length],
                          }}
                        />
                      </div>
                      <span className="font-mono text-[13px] text-muted-foreground flex-shrink-0">
                        {entry.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })()}
        </div>

        {/* CVE Inventory card */}
        <div
          className="bg-card rounded-xl border border-border p-4 tile-hover cursor-pointer flex flex-col"
          onClick={() => navigate("/inventory")}
        >
          <div className="tile-shine" />
          <div className="flex items-center justify-between mb-3">
            <h3 className="panel-title">CVE Inventory</h3>
            <Shield className="w-4 h-4 text-muted-foreground/50" />
          </div>
          {newCveStats.totalCves > 0 ? (
            <>
              <div className="flex items-end gap-2 mb-1">
                <div className="text-3xl font-bold text-foreground tabular-nums tracking-tight leading-none">
                  {newCveStats.totalCves}
                </div>
                {newCveStats.newCves > 0 && (
                  <span className="mb-0.5 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-red-600/20 text-red-400 border border-red-600/30">
                    +{newCveStats.newCves} new
                  </span>
                )}
              </div>
              <div className="text-[11px] text-muted-foreground font-mono uppercase tracking-wider mb-4">
                CVEs across all technologies
              </div>
              <div className="space-y-1.5 flex-1">
                {[
                  { label: "Critical", count: newCveStats.critical, newCount: newCveStats.newCritical, color: "bg-red-600" },
                  { label: "High",     count: newCveStats.high,     newCount: newCveStats.newHigh,     color: "bg-orange-500" },
                  { label: "Medium",   count: newCveStats.medium,   newCount: 0,                       color: "bg-yellow-500" },
                  { label: "Low",      count: newCveStats.low,      newCount: 0,                       color: "bg-blue-500" },
                ].map(({ label, count, newCount, color }) => (
                  <div key={label} className="flex items-center gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full flex-shrink-0 ${color}`} />
                    <span className="text-muted-foreground w-14">{label}</span>
                    <span className="font-mono text-foreground/80">{count}</span>
                    {newCount > 0 && (
                      <span className="text-[10px] font-mono text-red-400">+{newCount}</span>
                    )}
                    {count > 0 && (
                      <div className="flex-1 bg-secondary/50 rounded-full h-[2px] overflow-hidden">
                        <div
                          className={`${color} h-full rounded-full transition-all`}
                          style={{ width: `${Math.min(100, (count / (newCveStats.totalCves || 1)) * 100)}%` }}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <div className="mt-4 text-[10px] text-muted-foreground/50 font-mono">
                View inventory →
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-4">
              <Shield className="w-8 h-8 mb-2 text-muted-foreground/20" />
              <p className="text-xs text-muted-foreground">No inventory scan yet</p>
              <p className="text-[10px] text-muted-foreground/60 mt-1">Run CVE Inventory to populate</p>
            </div>
          )}
        </div>

        {/* Fleet Health */}
        <div className="bg-card rounded-xl border border-border p-4 tile-hover">
          <div className="tile-shine" />
          <div className="flex items-center justify-between mb-4">
            <h3 className="panel-title">Fleet Health</h3>
            <button
              onClick={() => navigate("/fleet")}
              className="text-xs text-muted-foreground hover:text-foreground/80 font-mono transition-colors"
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
                count: fleet.filter((f) => (f.status as string) === "stopped").length,
                color: "text-warn-400",
                dot: "bg-warn-400",
              },
              {
                label: "Terminated",
                count: fleet.filter((f) => (f.status as string) === "terminated").length,
                color: "text-muted-foreground",
                dot: "bg-accent",
              },
            ].map((row) => (
              <div
                key={row.label}
                onClick={() => navigate("/fleet")}
                className="flex items-center justify-between bg-background/50 rounded-lg px-3 py-2.5 cursor-pointer hover:bg-secondary/60 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${row.dot}`} />
                  <span className="text-xs text-foreground/80">{row.label}</span>
                </div>
                <span className={`text-sm font-bold font-mono ${row.color}`}>
                  {row.count}
                </span>
              </div>
            ))}
            <div className="pt-1">
              <div className="flex justify-between text-[13px] text-muted-foreground font-mono mb-1">
                <span>Capacity</span>
                <span>
                  {metrics.fleetUtilization > 0
                    ? (metrics.fleetUtilization * 100).toFixed(0)
                    : 0}
                  %
                </span>
              </div>
              <div className="w-full bg-secondary rounded h-1">
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
      </div>

      {/* Geo Map */}
      <div className="bg-card rounded-xl border border-border tile-hover">
        <div className="tile-shine" />
        <div className="px-4 py-3 border-b border-border">
          <h3 className="panel-title">Global Recon Map</h3>
        </div>
        <div className="p-4">
          <GeoMap targets={filteredTargets} onEnriched={onRefresh} />
        </div>
      </div>

      {/* Recent Scans + Top Assets */}
      <div className="flex flex-col lg:flex-row gap-4 items-start">

      {/* Recent Scans Table */}
      <div className="flex-1 bg-card rounded-xl border border-border overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="panel-title">Recent Scans</h3>
          <button
            className="text-xs text-muted-foreground hover:text-foreground/80 font-mono transition-colors disabled:opacity-40"
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? "Syncing..." : "↻ Refresh"}
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="border-b border-border">
              <tr className="text-[13px] text-muted-foreground font-mono">
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Found</th>
                <th className="px-4 py-2.5 font-medium">Vulns</th>
                <th className="px-4 py-2.5"></th>
              </tr>
            </thead>
            <tbody>
              {filteredTargets.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="px-5 py-12 text-center text-muted-foreground text-sm font-mono"
                  >
                    No scan data — run your first scan
                  </td>
                </tr>
              ) : (
                [...filteredTargets]
                  .sort(
                    (a, b) =>
                      new Date(b.lastScanDate || 0).getTime() -
                      new Date(a.lastScanDate || 0).getTime(),
                  )
                  .slice(0, 5)
                  .map((target) => (
                    <tr
                      key={target.id}
                      className="border-b border-border/50 hover:bg-secondary/20 transition-colors cursor-pointer"
                      onClick={() => navigate(`/targets/${target.id}`)}
                    >
                      <td className="px-4 py-3">
                        <div className="text-sm text-foreground font-mono">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.domain) }} />
                        </div>
                        <div className="text-xs text-muted-foreground font-mono mt-0.5">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(target.programName) }} />
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
                        <span className="text-sm font-mono text-foreground/90">
                          {getScanMetrics(target).count}
                        </span>
                        <span className="text-[13px] text-muted-foreground ml-1">
                          {getScanMetrics(target).label}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        {target.vulnerabilities?.length > 0 ? (
                          <span className="text-sm font-bold font-mono text-danger-400">
                            {target.vulnerabilities.length}
                          </span>
                        ) : (
                          <span className="text-sm text-muted-foreground/80 font-mono">
                            —
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        <ChevronRight className="w-4 h-4 text-muted-foreground/80" />
                      </td>
                    </tr>
                  ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Top Assets */}
      <div className="w-full lg:w-56 lg:flex-shrink-0 bg-card rounded-xl border border-border p-4 tile-hover flex flex-col">
        <div className="tile-shine" />
        <div className="flex items-center justify-between mb-4">
          <h3 className="panel-title">Top Assets</h3>
          <button
            onClick={() => navigate("/targets")}
            className="text-xs text-muted-foreground hover:text-foreground/80 font-mono transition-colors"
          >
            View all →
          </button>
        </div>
        <ul className="flex-1 overflow-y-auto scrollbar-purple max-h-[340px]">
          {getTopAssets(filteredTargets).length === 0 ? (
            <li className="text-muted-foreground text-[13px] text-center py-8 font-mono">
              No data yet
            </li>
          ) : (
            getTopAssets(filteredTargets).map((asset, idx) => (
              <li
                key={asset.name}
                onClick={() => {
                  const t = filteredTargets.find((t) => t.domain === asset.name);
                  if (t) navigate(`/targets/${t.id}`);
                  else navigate("/targets");
                }}
                className="flex items-center justify-between px-2 py-1.5 rounded-lg hover:bg-secondary/50 transition-colors group cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[14px] text-foreground/90 group-hover:text-foreground transition-colors truncate max-w-[160px]">
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

      </div>{/* end Recent Scans + Top Assets grid */}

    </div>
  );
};

const API_URL = "http://localhost:5000";

const AppWrapper = () => {
  const [auth, setAuth] = useState<{
    checked: boolean;
    required: boolean;
    authenticated: boolean;
    username: string | null;
    role: string | null;
  }>({
    checked: false,
    required: false,
    authenticated: false,
    username: null,
    role: null,
  });

  const fetchAuthStatus = async () => {
    try {
      const r = await fetch(`${API_URL}/api/auth/status`);
      if (!r.ok) {
        setAuth({
          checked: true,
          required: false,
          authenticated: true,
          username: null,
          role: null,
        });
        return;
      }
      const d = await r.json();
      setAuth({
        checked: true,
        required: Boolean(d.authRequired),
        authenticated: Boolean(d.authenticated),
        username: d.username || null,
        role: d.role || null,
      });
    } catch {
      setAuth({
        checked: true,
        required: false,
        authenticated: true,
        username: null,
        role: null,
      });
    }
  };

  useEffect(() => {
    // If Ghostwriter (or any external embedder) passes ?autoauth=<token>, store it
    // automatically so the user doesn't have to log in manually inside the iframe.
    const params = new URLSearchParams(window.location.search);
    const autoToken = params.get("autoauth");
    if (autoToken) {
      localStorage.setItem("ax_auth_token", autoToken);
      // Remove from URL so the token doesn't stay visible in the address bar.
      params.delete("autoauth");
      const newSearch = params.toString();
      const newUrl = window.location.pathname + (newSearch ? "?" + newSearch : "") + window.location.hash;
      window.history.replaceState({}, "", newUrl);
    }
    fetchAuthStatus();
  }, []);

  const handleLoginSuccess = (token: string) => {
    if (token) localStorage.setItem("ax_auth_token", token);
    fetchAuthStatus();
  };

  const handleLogout = async () => {
    try {
      await fetch(`${API_URL}/api/auth/logout`, { method: "POST" });
    } catch {}
    localStorage.removeItem("ax_auth_token");
    setAuth((a) => ({
      ...a,
      authenticated: false,
      username: null,
      role: null,
    }));
  };

  // Splash while we check auth status
  if (!auth.checked) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <BinocularsSkullLogo className="w-12 h-12 text-primary-400 animate-pulse" />
          <span className="text-muted-foreground text-sm font-mono">loading…</span>
        </div>
      </div>
    );
  }

  if (auth.required && !auth.authenticated) {
    return <LoginPage apiUrl={API_URL} onSuccess={handleLoginSuccess} />;
    }

  return (
    <Router>
      <App
        onLogout={auth.required ? handleLogout : undefined}
        username={auth.username}
        role={auth.role}
      />
    </Router>
  );
};
export default AppWrapper;
