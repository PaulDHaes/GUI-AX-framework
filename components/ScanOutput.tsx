import React, { useState, useEffect, useRef, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import {
  Terminal,
  Copy,
  Download,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Loader2,
  Image as ImageIcon,
  Filter,
  ChevronDown,
  ChevronUp,
  Search,
  Globe,
  Network,
  Shield,
  FolderSearch,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface Scan {
  id: string;
  name: string;
  module: string;
  targets: string[] | number;
  status: string;
  progress?: number;
  startTime?: string;
  startedAt?: string;
  endTime?: string;
  completedAt?: string;
  command?: string;
  logs?: string[];
  output?: string;
  date?: string;
  results?: number;
  runtime?: string;
  local_logs?: string;
  remote_logs?: string;
  instances?: number;
  threads?: number;
  failure_reason?: string;
  failure_lines?: string[];
}

interface Screenshot {
  url: string;
  filename: string;
  rel: string;
  domain: string;
}

/** Parsed line for structured modules */
interface ParsedLine {
  raw: string;
  url?: string;
  statusCode?: number;
  host?: string;
  port?: number;
  proto?: string;
  state?: string;
  service?: string;
  severity?: string;
  template?: string;
  ip?: string;
  title?: string;
  size?: number;
  words?: number;
  path?: string;
}

type ScanCategory =
  | "screenshot"
  | "http"
  | "port"
  | "vuln"
  | "fuzzing"
  | "dns"
  | "generic";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SCREENSHOT_MODULES = [
  "gowitness",
  "webscreenshot",
  "scrying",
  "aquatone",
];
const HTTP_MODULES = ["httpx", "httprobe"];
const PORT_MODULES = ["nmap", "masscan", "rustscan", "naabu", "nmapx"];
const VULN_MODULES = ["nuclei"];
const FUZZ_MODULES = [
  "ffuf",
  "dirsearch",
  "gobuster",
  "feroxbuster",
  "wfuzz",
  "dirdar",
];
const DNS_MODULES = [
  "dnsx",
  "subfinder",
  "amass",
  "assetfinder",
  "shuffledns",
  "puredns",
  "massdns",
  "hakrevdns",
];

function getScanCategory(module: string): ScanCategory {
  const m = module.toLowerCase();
  if (SCREENSHOT_MODULES.some((t) => m.includes(t))) return "screenshot";
  if (HTTP_MODULES.some((t) => m.includes(t))) return "http";
  if (PORT_MODULES.some((t) => m.includes(t))) return "port";
  if (VULN_MODULES.some((t) => m.includes(t))) return "vuln";
  if (FUZZ_MODULES.some((t) => m.includes(t))) return "fuzzing";
  if (DNS_MODULES.some((t) => m.includes(t))) return "dns";
  return "generic";
}

// httpx:  https://host [200] [Title] [tech1,tech2] [1234]
const RE_HTTPX =
  /^(https?:\/\/\S+)\s+\[(\d{3})\](?:\s+\[([^\]]*)\])?(?:\s+\[([^\]]*)\])?(?:\s+\[([^\]]*)\])?/;
// nmap port line: 80/tcp  open  http  Apache
const RE_NMAP =
  /^(\d+)\/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\s+(\S+)(?:\s+(.*))?/;
// nuclei: [template-id] [type] [severity] url
const RE_NUCLEI = /^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)/;
// ffuf/dirsearch: /path   [Status: 200, Size: 1234, Words: 100, Lines: 50]
const RE_FFUF =
  /^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+)(?:,\s*Lines:\s*(\d+))?/;

function parseLine(raw: string, cat: ScanCategory): ParsedLine {
  const line = raw.trim();
  switch (cat) {
    case "http": {
      const m = RE_HTTPX.exec(line);
      if (m)
        return {
          raw,
          url: m[1],
          statusCode: parseInt(m[2]),
          title: m[3] || undefined,
          tech: m[4] ? m[4].split(",").map((s) => s.trim()) : undefined,
          size: m[5] ? parseInt(m[5]) : undefined,
        } as ParsedLine;
      break;
    }
    case "port": {
      const m = RE_NMAP.exec(line);
      if (m)
        return {
          raw,
          port: parseInt(m[1]),
          proto: m[2],
          state: m[3],
          service: m[4],
        };
      break;
    }
    case "vuln": {
      const m = RE_NUCLEI.exec(line);
      if (m)
        return {
          raw,
          template: m[1],
          severity: m[3].toLowerCase(),
          url: m[4],
        };
      break;
    }
    case "fuzzing": {
      const m = RE_FFUF.exec(line);
      if (m)
        return {
          raw,
          path: m[1],
          statusCode: parseInt(m[2]),
          size: parseInt(m[3]),
          words: parseInt(m[4]),
        };
      break;
    }
    default:
      break;
  }
  return { raw };
}

function statusColor(code: number): string {
  if (code >= 200 && code < 300)
    return "bg-emerald-500/20 text-emerald-300 border-emerald-500/40";
  if (code >= 300 && code < 400)
    return "bg-blue-500/20 text-blue-300 border-blue-500/40";
  if (code >= 400 && code < 500)
    return "bg-amber-500/20 text-amber-300 border-amber-500/40";
  if (code >= 500) return "bg-red-500/20 text-red-300 border-red-500/40";
  return "bg-slate-500/20 text-slate-300 border-slate-500/40";
}

function severityColor(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-red-700/40 text-red-200 border-red-600/50";
    case "high":
      return "bg-orange-600/40 text-orange-200 border-orange-500/50";
    case "medium":
      return "bg-amber-500/40 text-amber-200 border-amber-400/50";
    case "low":
      return "bg-blue-500/40 text-blue-200 border-blue-400/50";
    case "info":
      return "bg-slate-500/40 text-slate-300 border-slate-400/50";
    default:
      return "bg-slate-600/30 text-slate-300 border-slate-500/40";
  }
}

function portStateColor(state: string): string {
  if (state === "open")
    return "bg-emerald-500/20 text-emerald-300 border-emerald-500/40";
  if (state === "filtered")
    return "bg-amber-500/20 text-amber-300 border-amber-500/40";
  return "bg-slate-500/20 text-slate-400 border-slate-500/40";
}

// ─── Component ───────────────────────────────────────────────────────────────

interface ScanOutputProps {
  apiUrl: string;
  scanId?: string;
}

export default function ScanOutput({ apiUrl, scanId }: ScanOutputProps) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const autoScrollRef = useRef(autoScroll);
  const [rawView, setRawView] = useState(false);
  const [screenshots, setScreenshots] = useState<Screenshot[]>([]);
  const [expandedShot, setExpandedShot] = useState<Screenshot | null>(null);
  const [logSearch, setLogSearch] = useState("");

  useEffect(() => {
    autoScrollRef.current = autoScroll;
  }, [autoScroll]);

  const handleOutputScroll = () => {
    const el = outputRef.current;
    if (!el) return;

    // If the user scrolls away from the bottom, stop auto-scrolling.
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    if (atBottom !== autoScrollRef.current) {
      setAutoScroll(atBottom);
    }
  };
  // Per-category filter states
  const [statusFilter, setStatusFilter] = useState<Set<number>>(new Set());
  const [stateFilter, setStateFilter] = useState<Set<string>>(new Set());
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());
  const [showOpenOnly, setShowOpenOnly] = useState(false);

  const outputRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!scanId) return;
    fetchScanDetails();
    // Removed auto-refresh interval - now only fetches on load
  }, [scanId]);

  useEffect(() => {
    if (autoScroll && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [scan?.logs, autoScroll]);

  const fetchScanDetails = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const response = await fetch(
        `${apiUrl}/api/axiom/scans/${encodeURIComponent(scanId)}`,
      );
      if (response.ok) {
        const data = await response.json();
        setScan(data);

        const hasLogs = Array.isArray(data.logs) ? data.logs.length > 0 : false;
        if (!hasLogs) {
          fetchScanLogs(data.id || scanId);
        }

        const cat = getScanCategory(data.module || "");
        if (cat === "screenshot") fetchScreenshots(data.id);
      }
    } catch (err) {
      console.error("Failed to fetch scan details:", err);
    } finally {
      setLoading(false);
    }
  };

  const fetchScanLogs = async (id: string) => {
    try {
      const r = await fetch(
        `${apiUrl}/api/axiom/scans/${encodeURIComponent(id)}/logs`,
      );
      if (r.ok) {
        const data = await r.json();
        if (data?.logs) {
          setScan((prev) => (prev ? { ...prev, logs: data.logs } : prev));
        }
      }
    } catch {
      /* ignore */
    }
  };

  const fetchScreenshots = async (id: string) => {
    try {
      const r = await fetch(
        `${apiUrl}/api/axiom/scans/${encodeURIComponent(id)}/screenshots`,
      );
      if (r.ok) {
        const data = await r.json();
        setScreenshots(data);
      }
    } catch {
      /* ignore */
    }
  };

  const copyCommand = () => {
    if (scan?.command) navigator.clipboard.writeText(scan.command);
  };

  const downloadLogs = () => {
    if (!scan?.logs) return;
    const blob = new Blob([scan.logs.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${scan.name}-logs.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Derived data ──────────────────────────────────────────────────────────

  const category = useMemo(
    () => getScanCategory(scan?.module || ""),
    [scan?.module],
  );

  const parsedLines = useMemo<ParsedLine[]>(() => {
    if (!scan?.logs) return [];
    return scan.logs
      .map((l) => parseLine(l, category))
      .filter((l) => l.raw.trim().length > 0);
  }, [scan?.logs, category]);

  // Collect unique values for filter chips
  const allStatusCodes = useMemo(
    () =>
      [
        ...new Set(
          parsedLines.map((l) => l.statusCode).filter(Boolean) as number[],
        ),
      ].sort((a, b) => a - b),
    [parsedLines],
  );
  const allSeverities = useMemo(
    () =>
      [
        ...new Set(
          parsedLines.map((l) => l.severity).filter(Boolean) as string[],
        ),
      ].sort(),
    [parsedLines],
  );
  const allStates = useMemo(
    () =>
      [
        ...new Set(parsedLines.map((l) => l.state).filter(Boolean) as string[]),
      ].sort(),
    [parsedLines],
  );

  const filteredLines = useMemo<ParsedLine[]>(() => {
    return parsedLines.filter((l) => {
      if (
        statusFilter.size > 0 &&
        l.statusCode !== undefined &&
        !statusFilter.has(l.statusCode)
      )
        return false;
      if (
        sevFilter.size > 0 &&
        l.severity !== undefined &&
        !sevFilter.has(l.severity)
      )
        return false;
      if (
        stateFilter.size > 0 &&
        l.state !== undefined &&
        !stateFilter.has(l.state)
      )
        return false;
      if (showOpenOnly && l.state !== undefined && l.state !== "open")
        return false;
      if (logSearch) {
        const q = logSearch.toLowerCase();
        if (!l.raw.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [
    parsedLines,
    statusFilter,
    sevFilter,
    stateFilter,
    showOpenOnly,
    logSearch,
  ]);

  const displayLines = category === "generic" ? parsedLines : filteredLines;
  const activeFilterCount =
    statusFilter.size +
    sevFilter.size +
    stateFilter.size +
    (showOpenOnly ? 1 : 0);

  const toggleStatus = (code: number) =>
    setStatusFilter((prev) => {
      const next = new Set(prev);
      next.has(code) ? next.delete(code) : next.add(code);
      return next;
    });
  const toggleSeverity = (sev: string) =>
    setSevFilter((prev) => {
      const next = new Set(prev);
      next.has(sev) ? next.delete(sev) : next.add(sev);
      return next;
    });
  const toggleState = (state: string) =>
    setStateFilter((prev) => {
      const next = new Set(prev);
      next.has(state) ? next.delete(state) : next.add(state);
      return next;
    });

  // ── Status helpers ────────────────────────────────────────────────────────

  const getStatusIcon = () => {
    switch (scan?.status) {
      case "running":
        return <Loader2 className="w-5 h-5 animate-spin text-amber-500" />;
      case "completed":
        return <CheckCircle2 className="w-5 h-5 text-emerald-500" />;
      case "failed":
        return <XCircle className="w-5 h-5 text-red-500" />;
      default:
        return <Terminal className="w-5 h-5 text-slate-500" />;
    }
  };

  const getStatusBadgeColor = () => {
    switch (scan?.status) {
      case "running":
        return "bg-amber-500/10 text-amber-300 border-amber-500/50";
      case "completed":
        return "bg-emerald-500/10 text-emerald-300 border-emerald-500/50";
      case "failed":
        return "bg-red-500/10 text-red-300 border-red-500/50";
      default:
        return "bg-slate-500/10 text-slate-400 border-slate-500/50";
    }
  };

  // ── Category icon ─────────────────────────────────────────────────────────
  const CategoryIcon = () => {
    switch (category) {
      case "screenshot":
        return <ImageIcon className="w-4 h-4 text-purple-400" />;
      case "http":
        return <Globe className="w-4 h-4 text-blue-400" />;
      case "port":
        return <Network className="w-4 h-4 text-cyan-400" />;
      case "vuln":
        return <Shield className="w-4 h-4 text-red-400" />;
      case "fuzzing":
        return <FolderSearch className="w-4 h-4 text-amber-400" />;
      case "dns":
        return <Globe className="w-4 h-4 text-emerald-400" />;
      default:
        return <Terminal className="w-4 h-4 text-slate-400" />;
    }
  };

  // ── Early returns ─────────────────────────────────────────────────────────

  if (!scanId) {
    return (
      <Card className="bg-slate-800 border-slate-700">
        <CardContent className="p-12 text-center">
          <Terminal className="w-16 h-16 mx-auto mb-4 text-slate-600" />
          <p className="text-slate-400 text-lg mb-2">No scan selected</p>
          <p className="text-slate-500 text-sm">
            Select a scan to view its output
          </p>
        </CardContent>
      </Card>
    );
  }

  if (!scan) {
    return (
      <Card className="bg-slate-800 border-slate-700">
        <CardContent className="p-12 text-center">
          <Loader2 className="w-16 h-16 mx-auto mb-4 text-primary-500 animate-spin" />
          <p className="text-slate-400">Loading scan details...</p>
        </CardContent>
      </Card>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      {/* Failure Banner */}
      {scan.status === "failed" && scan.failure_reason && (
        <div className="bg-red-950/60 border border-red-800 rounded-lg p-4 space-y-2">
          <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
            <XCircle className="h-4 w-4 shrink-0" />
            Scan failed — {scan.failure_reason}
          </div>
          {scan.failure_lines && scan.failure_lines.length > 0 && (
            <div className="mt-2 space-y-1">
              {scan.failure_lines.map((line, i) => (
                <div
                  key={i}
                  className="font-mono text-xs text-red-300 bg-red-950/40 px-2 py-1 rounded"
                >
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Header card */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              {getStatusIcon()}
              <div>
                <CardTitle className="text-white text-xl">
                  {scan.name}
                </CardTitle>
                <div className="text-sm text-slate-400 flex items-center gap-2 mt-1">
                  <CategoryIcon />
                  <Badge variant="outline" className="text-xs">
                    {scan.module}
                  </Badge>
                  <span className="text-slate-500 text-xs">{category}</span>
                </div>
              </div>
            </div>
            <Badge className={`${getStatusBadgeColor()} border`}>
              {scan.status.toUpperCase()}
            </Badge>
          </div>

          {/* Stats strip */}
          <div className="flex flex-wrap gap-4 pt-3 border-t border-slate-700 mt-3">
            {scan.results !== undefined && (
              <div>
                <span className="text-slate-500 text-xs">Results</span>
                <div
                  className={`text-lg font-bold ${scan.results > 0 ? "text-emerald-400" : "text-slate-400"}`}
                >
                  {scan.results}
                </div>
              </div>
            )}
            {scan.instances !== undefined && scan.instances > 0 && (
              <div>
                <span className="text-slate-500 text-xs">Instances</span>
                <div className="text-lg font-bold text-amber-400">
                  {scan.instances}
                </div>
              </div>
            )}
            {scan.threads !== undefined && scan.threads > 0 && (
              <div>
                <span className="text-slate-500 text-xs">Threads</span>
                <div className="text-lg font-bold text-blue-400">
                  {scan.threads}
                </div>
              </div>
            )}
            {scan.runtime && (
              <div>
                <span className="text-slate-500 text-xs">Runtime</span>
                <div className="text-lg font-bold text-primary-400 font-mono">
                  {scan.runtime}
                </div>
              </div>
            )}
            {typeof scan.targets === "number" && scan.targets > 0 && (
              <div>
                <span className="text-slate-500 text-xs">Targets</span>
                <div className="text-lg font-bold text-slate-300">
                  {scan.targets}
                </div>
              </div>
            )}
            {category === "screenshot" && screenshots.length > 0 && (
              <div>
                <span className="text-slate-500 text-xs">Screenshots</span>
                <div className="text-lg font-bold text-purple-400">
                  {screenshots.length}
                </div>
              </div>
            )}
          </div>
        </CardHeader>
      </Card>

      {/* Command */}
      {scan.command && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-white text-base flex items-center gap-2">
                <Terminal className="w-4 h-4 text-primary-400" />
                Command
              </CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={copyCommand}
                className="text-xs"
              >
                <Copy className="w-3 h-3 mr-1" />
                Copy
              </Button>
            </div>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="bg-slate-950 border border-slate-700 rounded-lg p-4 overflow-x-auto">
              <code className="text-sm text-emerald-400 font-mono break-all whitespace-pre-wrap">
                {scan.command}
              </code>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── SCREENSHOTS ────────────────────────────────────────────────────── */}
      {category === "screenshot" && screenshots.length > 0 && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader className="pb-3">
            <CardTitle className="text-white text-base flex items-center gap-2">
              <ImageIcon className="w-4 h-4 text-purple-400" />
              Screenshots ({screenshots.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {screenshots.map((shot) => (
                <div
                  key={shot.rel}
                  className="group relative border border-slate-700 rounded-lg overflow-hidden bg-slate-900 cursor-pointer hover:border-purple-500/60 transition-colors"
                  onClick={() => setExpandedShot(shot)}
                >
                  {/* Taller image card: h-64 gives plenty of vertical space to see page content */}
                  <div className="w-full h-64 bg-slate-950 flex items-center justify-center overflow-hidden">
                    <img
                      src={`${apiUrl}${shot.url}`}
                      alt={shot.domain}
                      className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform duration-200"
                      loading="lazy"
                      onError={(e) => {
                        (e.target as HTMLImageElement).style.display = "none";
                        (
                          e.target as HTMLImageElement
                        ).parentElement!.innerHTML =
                          `<div class="text-slate-600 text-xs text-center p-4">No preview</div>`;
                      }}
                    />
                  </div>
                  <div className="px-2 py-1.5 bg-slate-900/90 border-t border-slate-700">
                    <p
                      className="text-xs text-slate-300 font-mono truncate"
                      title={shot.domain}
                    >
                      {shot.domain}
                    </p>
                  </div>
                  {/* Expand hint */}
                  <div className="absolute inset-0 bg-black/0 group-hover:bg-black/10 transition-colors flex items-center justify-center opacity-0 group-hover:opacity-100">
                    <span className="text-white text-xs bg-black/60 rounded px-2 py-1">
                      Click to expand
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Screenshot lightbox */}
      {expandedShot && (
        <div
          className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4"
          onClick={() => setExpandedShot(null)}
        >
          <div
            className="relative max-w-5xl w-full bg-slate-900 rounded-xl border border-slate-600 overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-2 border-b border-slate-700">
              <span className="font-mono text-sm text-slate-300">
                {expandedShot.domain}
              </span>
              <button
                className="text-slate-400 hover:text-white transition-colors text-lg leading-none"
                onClick={() => setExpandedShot(null)}
              >
                ✕
              </button>
            </div>
            <div className="max-h-[80vh] overflow-auto">
              <img
                src={`${apiUrl}${expandedShot.url}`}
                alt={expandedShot.domain}
                className="w-full"
              />
            </div>
          </div>
        </div>
      )}

      {/* ── RESULTS / LOGS ─────────────────────────────────────────────────── */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-white text-base flex items-center gap-2">
              <Terminal className="w-4 h-4 text-primary-400" />
              Scan Results
              {activeFilterCount > 0 && (
                <Badge className="ml-1 bg-primary-600/30 text-primary-300 border-primary-500/40 text-xs">
                  {displayLines.length} / {parsedLines.length}
                </Badge>
              )}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRawView((prev) => !prev)}
                className="text-xs"
                title={rawView ? "Show parsed results" : "Show raw log"}
              >
                {rawView ? (
                  <Terminal className="w-3 h-3 mr-1" />
                ) : (
                  <Terminal className="w-3 h-3 mr-1" />
                )}
                {rawView ? "Parsed" : "Raw"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setAutoScroll((prev) => !prev)}
                className="text-xs"
                title={
                  autoScroll ? "Auto-scroll enabled" : "Auto-scroll paused"
                }
              >
                {autoScroll ? (
                  <ChevronDown className="w-3 h-3 mr-1" />
                ) : (
                  <ChevronUp className="w-3 h-3 mr-1" />
                )}
                {autoScroll ? "Auto" : "Pause"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={downloadLogs}
                disabled={!scan.logs?.length}
                className="text-xs"
              >
                <Download className="w-3 h-3 mr-1" />
                Export
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={fetchScanDetails}
                disabled={loading}
                className="text-xs"
              >
                <RefreshCw
                  className={`w-3 h-3 mr-1 ${loading ? "animate-spin" : ""}`}
                />
                Refresh
              </Button>
            </div>
          </div>

          {/* ── Search bar (always visible when there are lines) ── */}
          {parsedLines.length > 0 && (
            <div className="relative mt-2">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search results…"
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-white placeholder:text-slate-600 focus:outline-none focus:border-primary-500"
              />
              {logSearch && (
                <button
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white"
                  onClick={() => setLogSearch("")}
                >
                  ✕
                </button>
              )}
            </div>
          )}

          {/* ── HTTP / Fuzzing status-code filter ── */}
          {(category === "http" || category === "fuzzing") &&
            allStatusCodes.length > 0 && (
              <div className="mt-3 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs text-slate-500">
                  <Filter className="w-3 h-3" /> Status codes
                  {statusFilter.size > 0 && (
                    <button
                      className="ml-1 text-primary-400 hover:text-primary-300"
                      onClick={() => setStatusFilter(new Set())}
                    >
                      clear
                    </button>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {allStatusCodes.map((code) => {
                    const count = parsedLines.filter(
                      (l) => l.statusCode === code,
                    ).length;
                    const active = statusFilter.has(code);
                    return (
                      <button
                        key={code}
                        onClick={() => toggleStatus(code)}
                        className={`px-2 py-0.5 rounded border text-xs font-mono font-semibold transition-all ${
                          active
                            ? statusColor(code) +
                              " ring-1 ring-offset-0 ring-current"
                            : "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500"
                        }`}
                      >
                        {code}
                        <span className="ml-1 opacity-60">({count})</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

          {/* ── Nuclei severity filter ── */}
          {category === "vuln" && allSeverities.length > 0 && (
            <div className="mt-3 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs text-slate-500">
                <Filter className="w-3 h-3" /> Severity
                {sevFilter.size > 0 && (
                  <button
                    className="ml-1 text-primary-400 hover:text-primary-300"
                    onClick={() => setSevFilter(new Set())}
                  >
                    clear
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allSeverities.map((sev) => {
                  const count = parsedLines.filter(
                    (l) => l.severity === sev,
                  ).length;
                  const active = sevFilter.has(sev);
                  return (
                    <button
                      key={sev}
                      onClick={() => toggleSeverity(sev)}
                      className={`px-2 py-0.5 rounded border text-xs font-semibold capitalize transition-all ${
                        active
                          ? severityColor(sev) +
                            " ring-1 ring-offset-0 ring-current"
                          : "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500"
                      }`}
                    >
                      {sev}
                      <span className="ml-1 opacity-60">({count})</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── Port state filter ── */}
          {category === "port" && allStates.length > 0 && (
            <div className="mt-3 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs text-slate-500">
                <Filter className="w-3 h-3" /> Port state
              </div>
              <div className="flex flex-wrap gap-1.5">
                {allStates.map((st) => {
                  const count = parsedLines.filter(
                    (l) => l.state === st,
                  ).length;
                  const active = stateFilter.has(st);
                  return (
                    <button
                      key={st}
                      onClick={() => toggleState(st)}
                      className={`px-2 py-0.5 rounded border text-xs font-semibold transition-all ${
                        active
                          ? portStateColor(st) +
                            " ring-1 ring-offset-0 ring-current"
                          : "bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-500"
                      }`}
                    >
                      {st}
                      <span className="ml-1 opacity-60">({count})</span>
                    </button>
                  );
                })}
              </div>
              {allStates.includes("open") && (
                <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none mt-1">
                  <input
                    type="checkbox"
                    checked={showOpenOnly}
                    onChange={(e) => {
                      setShowOpenOnly(e.target.checked);
                      if (e.target.checked) setStateFilter(new Set());
                    }}
                    className="accent-emerald-500"
                  />
                  Show open ports only
                </label>
              )}
            </div>
          )}
        </CardHeader>

        <CardContent className="pt-0">
          {/* ── Structured result rows ── */}
          {rawView ? (
            <div
              ref={outputRef}
              onScroll={handleOutputScroll}
              className="bg-slate-950 border border-slate-700 rounded-lg overflow-y-auto"
              style={{
                maxHeight: category === "screenshot" ? "28rem" : "36rem",
              }}
            >
              <pre className="m-0 p-3 text-xs font-mono whitespace-pre-wrap break-words">
                {scan?.logs?.join("\n")}
              </pre>
            </div>
          ) : displayLines.length > 0 ? (
            <div
              ref={outputRef}
              onScroll={handleOutputScroll}
              className="bg-slate-950 border border-slate-700 rounded-lg overflow-y-auto"
              style={{
                maxHeight: category === "screenshot" ? "28rem" : "36rem",
              }}
            >
              {category === "http" || category === "fuzzing" ? (
                // Table-style for HTTP/fuzzing results
                <table className="w-full text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900 border-b border-slate-700">
                    <tr>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold w-16">
                        Code
                      </th>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold">
                        URL / Path
                      </th>
                      {category === "http" && (
                        <th className="px-3 py-2 text-left text-slate-400 font-semibold hidden md:table-cell">
                          Title
                        </th>
                      )}
                      {category === "fuzzing" && (
                        <th className="px-3 py-2 text-left text-slate-400 font-semibold hidden md:table-cell w-24">
                          Size
                        </th>
                      )}
                      {category === "fuzzing" && (
                        <th className="px-3 py-2 text-left text-slate-400 font-semibold hidden lg:table-cell w-20">
                          Words
                        </th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {displayLines.map((l, i) => (
                      <tr
                        key={i}
                        className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors"
                      >
                        <td className="px-3 py-1.5">
                          {l.statusCode !== undefined ? (
                            <span
                              className={`px-1.5 py-0.5 rounded border text-xs font-bold ${statusColor(l.statusCode)}`}
                            >
                              {l.statusCode}
                            </span>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>
                        <td className="px-3 py-1.5 text-slate-200 break-all max-w-xs">
                          {l.url || l.path || l.raw}
                        </td>
                        {category === "http" && (
                          <td className="px-3 py-1.5 text-slate-400 hidden md:table-cell max-w-[200px] truncate">
                            {l.title || ""}
                          </td>
                        )}
                        {category === "fuzzing" && (
                          <td className="px-3 py-1.5 text-slate-400 hidden md:table-cell">
                            {l.size !== undefined
                              ? l.size.toLocaleString()
                              : ""}
                          </td>
                        )}
                        {category === "fuzzing" && (
                          <td className="px-3 py-1.5 text-slate-400 hidden lg:table-cell">
                            {l.words !== undefined
                              ? l.words.toLocaleString()
                              : ""}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : category === "port" ? (
                // Port scan table
                <table className="w-full text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900 border-b border-slate-700">
                    <tr>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold w-24">
                        Port
                      </th>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold w-24">
                        State
                      </th>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold">
                        Service
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayLines.map((l, i) =>
                      l.port !== undefined ? (
                        <tr
                          key={i}
                          className="border-b border-slate-800/60 hover:bg-slate-800/30"
                        >
                          <td className="px-3 py-1.5 text-cyan-300 font-bold">
                            {l.port}/{l.proto || "tcp"}
                          </td>
                          <td className="px-3 py-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded border text-xs ${portStateColor(l.state || "")}`}
                            >
                              {l.state}
                            </span>
                          </td>
                          <td className="px-3 py-1.5 text-slate-300">
                            {l.service || ""}
                          </td>
                        </tr>
                      ) : (
                        <tr key={i} className="border-b border-slate-800/30">
                          <td colSpan={3} className="px-3 py-1 text-slate-500">
                            {l.raw}
                          </td>
                        </tr>
                      ),
                    )}
                  </tbody>
                </table>
              ) : category === "vuln" ? (
                // Nuclei findings table
                <table className="w-full text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900 border-b border-slate-700">
                    <tr>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold w-24">
                        Severity
                      </th>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold w-40">
                        Template
                      </th>
                      <th className="px-3 py-2 text-left text-slate-400 font-semibold">
                        Target
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayLines.map((l, i) =>
                      l.severity ? (
                        <tr
                          key={i}
                          className="border-b border-slate-800/60 hover:bg-slate-800/30"
                        >
                          <td className="px-3 py-1.5">
                            <span
                              className={`px-1.5 py-0.5 rounded border text-xs font-bold capitalize ${severityColor(l.severity)}`}
                            >
                              {l.severity}
                            </span>
                          </td>
                          <td className="px-3 py-1.5 text-slate-300 truncate max-w-[160px]">
                            {l.template}
                          </td>
                          <td className="px-3 py-1.5 text-slate-200 break-all">
                            {l.url}
                          </td>
                        </tr>
                      ) : (
                        <tr key={i} className="border-b border-slate-800/30">
                          <td colSpan={3} className="px-3 py-1 text-slate-500">
                            {l.raw}
                          </td>
                        </tr>
                      ),
                    )}
                  </tbody>
                </table>
              ) : (
                // Generic / DNS / screenshot module — plain log lines
                <div className="p-3 space-y-0.5">
                  {displayLines.map((l, i) => (
                    <div
                      key={i}
                      className={`text-xs leading-5 ${
                        l.raw.toLowerCase().includes("error")
                          ? "text-red-400"
                          : l.raw.toLowerCase().includes("warning")
                            ? "text-amber-400"
                            : l.raw.toLowerCase().includes("success")
                              ? "text-emerald-400"
                              : "text-slate-300"
                      }`}
                    >
                      <span className="text-slate-700 mr-2 select-none">
                        [{i + 1}]
                      </span>
                      {l.raw}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : scan.logs && scan.logs.length > 0 ? (
            <div className="text-center py-8 text-slate-500 text-sm">
              No results match the current filters
            </div>
          ) : (
            <div className="text-center py-8 text-slate-600 text-sm">
              No output yet
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan metadata */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader className="pb-2">
          <CardTitle className="text-white text-base">Scan Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-slate-500">Scan ID</span>
              <div className="text-white font-mono mt-1 text-xs break-all">
                {scan.id}
              </div>
            </div>
            <div>
              <span className="text-slate-500">Module</span>
              <div className="text-white font-mono mt-1">{scan.module}</div>
            </div>
            <div>
              <span className="text-slate-500">Start Time</span>
              <div className="text-white mt-1 text-xs">
                {scan.date ||
                  (scan.startedAt
                    ? new Date(scan.startedAt).toLocaleString()
                    : "N/A")}
              </div>
            </div>
            <div>
              <span className="text-slate-500">Runtime</span>
              <div className="text-white font-mono mt-1">
                {scan.runtime || "N/A"}
              </div>
            </div>
            {scan.output && (
              <div className="col-span-2">
                <span className="text-slate-500">Output Path</span>
                <div className="text-slate-300 font-mono mt-1 text-xs break-all">
                  {scan.output}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
