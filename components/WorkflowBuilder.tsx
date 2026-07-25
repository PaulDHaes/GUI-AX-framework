import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Play,
  Plus,
  Trash2,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Globe,
  Server,
  Shield,
  Camera,
  Search,
  Zap,
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  Network,
  Eye,
  X,
  RotateCcw,
  Layers,
  AlertTriangle,
  StopCircle,
  ChevronRight,
  Settings2,
  Terminal,
  ScanLine,
  Link2,
  Shuffle,
  Cpu,
  GitBranch,
  CornerDownRight,
  FileText,
  Bookmark,
} from "lucide-react";
import {
  PROVISIONER_LABELS,
  isModuleAvailable,
  getRequiredProvisioners,
} from "../services/provisioner";

// ─── Types ───────────────────────────────────────────────────────────────────

type InputType = "ips" | "domains" | "subdomains" | "urls" | "mixed";
type StepStatus = "pending" | "running" | "completed" | "failed" | "skipped";
type WorkflowStatus = "idle" | "running" | "completed" | "failed" | "aborted";

interface ModuleInfo {
  name: string;
  label: string;
  category:
    | "enum"
    | "dns"
    | "port"
    | "http"
    | "vuln"
    | "screenshot"
    | "fuzz"
    | "url"
    | "tech";
  accepts: InputType[];
  outputType: InputType;
  description: string;
  /** 1 (very light) → 5 (very demanding) — drives default fleet size */
  weight: 1 | 2 | 3 | 4 | 5;
  colorClass: string;
  textClass: string;
  borderClass: string;
  Icon: React.ComponentType<{ className?: string }>;
}

interface BuilderStep {
  id: string;
  module: ModuleInfo;
  customArgs: string;
  enabled: boolean;
  /** per-step instance count override; if undefined, derived from workflow min/max + module weight */
  fleetSize?: number;
  /**
   * Upstream step ids feeding this step.
   *  - undefined / [] → root (consumes the workflow's initial targets)
   *  - 1 entry      → sequential link (consumes that parent's output)
   *  - 2+ entries   → fan-in / convergence (waits for ALL parents, merges + dedupes their outputs)
   * `parentIds[0]` is the "primary parent" used for tree-style display only.
   */
  parentIds?: string[];
}

interface ExecutingStep extends BuilderStep {
  status: StepStatus;
  scanId?: string;
  startTime?: Date;
  endTime?: Date;
  resultCount?: number;
  outputLines?: string[];
  error?: string;
}

interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  inputType: InputType;
  /**
   * Ordered step list. Built-in templates only carry `module`/`customArgs` and
   * are chained sequentially on load. User-saved templates additionally carry
   * `localId`/`parentLocalIds`/`fleetSize` so branch/fan-in structure survives
   * a save→load round-trip (loadTemplate remaps localIds to fresh step ids).
   */
  steps: Array<{
    module: string;
    customArgs?: string;
    localId?: string;
    parentLocalIds?: string[];
    fleetSize?: number;
  }>;
  tags: string[];
  difficulty: "easy" | "medium" | "advanced";
  /** true for templates the user saved from their own pipeline (deletable). */
  custom?: boolean;
  /** ISO string; only set on custom templates. */
  createdAt?: string;
}

interface WorkflowRun {
  id: string;
  name: string;
  inputType: InputType;
  initialTargets: string[];
  steps: ExecutingStep[];
  status: WorkflowStatus;
  startTime?: Date;
  endTime?: Date;
  currentStepIndex: number;
  abortRequested?: boolean;
}

// ─── Module catalog ───────────────────────────────────────────────────────────

const M = (
  name: string,
  label: string,
  category: ModuleInfo["category"],
  accepts: InputType[],
  outputType: InputType,
  description: string,
  weight: ModuleInfo["weight"],
  color: string,
  text: string,
  border: string,
  Icon: React.ComponentType<{ className?: string }>,
): ModuleInfo => ({
  name,
  label,
  category,
  accepts,
  outputType,
  description,
  weight,
  colorClass: color,
  textClass: text,
  borderClass: border,
  Icon,
});

// weight scale: 1 = very light (API calls, dns), 3 = moderate (port scans, http), 5 = very heavy (vuln scans, fuzzing, screenshots)
const MODULE_CATALOG: ModuleInfo[] = [
  M(
    "subfinder",
    "Subfinder",
    "enum",
    ["domains", "mixed"],
    "subdomains",
    "Passive subdomain discovery via public APIs",
    1,
    "bg-cyan-500/15",
    "text-cyan-400",
    "border-cyan-500/30",
    Globe,
  ),
  M(
    "amass",
    "Amass",
    "enum",
    ["domains", "mixed"],
    "subdomains",
    "Active & passive subdomain enumeration",
    3,
    "bg-cyan-500/15",
    "text-cyan-400",
    "border-cyan-500/30",
    Globe,
  ),
  M(
    "assetfinder",
    "Assetfinder",
    "enum",
    ["domains", "mixed"],
    "subdomains",
    "Fast subdomain discovery",
    1,
    "bg-cyan-500/15",
    "text-cyan-400",
    "border-cyan-500/30",
    Globe,
  ),
  M(
    "dnsx",
    "DNSX",
    "dns",
    ["subdomains", "domains", "mixed"],
    "subdomains",
    "DNS resolution and validation",
    1,
    "bg-blue-500/15",
    "text-blue-400",
    "border-blue-500/30",
    Network,
  ),
  M(
    "massdns",
    "MassDNS",
    "dns",
    ["subdomains", "mixed"],
    "subdomains",
    "High-performance DNS stub resolver",
    2,
    "bg-blue-500/15",
    "text-blue-400",
    "border-blue-500/30",
    Network,
  ),
  M(
    "nmap",
    "Nmap",
    "port",
    ["ips", "subdomains", "domains", "mixed"],
    "ips",
    "Port scanning and service detection",
    4,
    "bg-orange-500/15",
    "text-orange-400",
    "border-orange-500/30",
    Server,
  ),
  M(
    "naabu",
    "Naabu",
    "port",
    ["ips", "subdomains", "domains", "mixed"],
    "ips",
    "Fast port scanner by ProjectDiscovery",
    3,
    "bg-orange-500/15",
    "text-orange-400",
    "border-orange-500/30",
    Server,
  ),
  M(
    "masscan",
    "Masscan",
    "port",
    ["ips", "mixed"],
    "ips",
    "Ultra-fast port scanner for large IP ranges",
    4,
    "bg-orange-500/15",
    "text-orange-400",
    "border-orange-500/30",
    Server,
  ),
  M(
    "rustscan",
    "RustScan",
    "port",
    ["ips", "subdomains", "mixed"],
    "ips",
    "Modern blazing-fast port scanner",
    3,
    "bg-orange-500/15",
    "text-orange-400",
    "border-orange-500/30",
    Server,
  ),
  M(
    "httpx",
    "HTTPX",
    "http",
    ["subdomains", "ips", "domains", "urls", "mixed"],
    "urls",
    "HTTP probe — find live web services",
    2,
    "bg-emerald-500/15",
    "text-emerald-400",
    "border-emerald-500/30",
    Activity,
  ),
  M(
    "httprobe",
    "Httprobe",
    "http",
    ["subdomains", "domains", "mixed"],
    "urls",
    "Simple alive HTTP probe",
    2,
    "bg-emerald-500/15",
    "text-emerald-400",
    "border-emerald-500/30",
    Activity,
  ),
  M(
    "nuclei",
    "Nuclei",
    "vuln",
    ["urls", "ips", "subdomains", "mixed"],
    "urls",
    "Template-based vulnerability scanner",
    5,
    "bg-red-500/15",
    "text-red-400",
    "border-red-500/30",
    Shield,
  ),
  M(
    "jaeles",
    "Jaeles",
    "vuln",
    ["urls", "mixed"],
    "urls",
    "Web application security scanner",
    5,
    "bg-red-500/15",
    "text-red-400",
    "border-red-500/30",
    Shield,
  ),
  M(
    "gowitness",
    "GoWitness",
    "screenshot",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Web screenshot capture",
    4,
    "bg-purple-500/15",
    "text-purple-400",
    "border-purple-500/30",
    Camera,
  ),
  M(
    "aquatone",
    "Aquatone",
    "screenshot",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Visual inspection of websites",
    4,
    "bg-purple-500/15",
    "text-purple-400",
    "border-purple-500/30",
    Camera,
  ),
  M(
    "gau",
    "GAU",
    "url",
    ["domains", "urls", "mixed"],
    "urls",
    "Fetch known URLs from AlienVault, Wayback etc.",
    2,
    "bg-yellow-500/15",
    "text-yellow-400",
    "border-yellow-500/30",
    Search,
  ),
  M(
    "katana",
    "Katana",
    "url",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Next-gen web crawler",
    3,
    "bg-yellow-500/15",
    "text-yellow-400",
    "border-yellow-500/30",
    Search,
  ),
  M(
    "gospider",
    "GoSpider",
    "url",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Fast web spider",
    3,
    "bg-yellow-500/15",
    "text-yellow-400",
    "border-yellow-500/30",
    Search,
  ),
  M(
    "waybackurls",
    "Waybackurls",
    "url",
    ["domains", "urls", "mixed"],
    "urls",
    "Fetch URLs from Wayback Machine",
    1,
    "bg-yellow-500/15",
    "text-yellow-400",
    "border-yellow-500/30",
    Search,
  ),
  M(
    "hakrawler",
    "Hakrawler",
    "url",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Simple fast web crawler",
    3,
    "bg-yellow-500/15",
    "text-yellow-400",
    "border-yellow-500/30",
    Search,
  ),
  M(
    "ffuf",
    "FFUF",
    "fuzz",
    ["urls", "mixed"],
    "urls",
    "Fast web fuzzer for directories and files",
    5,
    "bg-pink-500/15",
    "text-pink-400",
    "border-pink-500/30",
    Zap,
  ),
  M(
    "feroxbuster",
    "Feroxbuster",
    "fuzz",
    ["urls", "mixed"],
    "urls",
    "Recursive content discovery tool",
    5,
    "bg-pink-500/15",
    "text-pink-400",
    "border-pink-500/30",
    Zap,
  ),
  M(
    "gobuster",
    "Gobuster",
    "fuzz",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Directory and file brute-forcer",
    4,
    "bg-pink-500/15",
    "text-pink-400",
    "border-pink-500/30",
    Zap,
  ),
  M(
    "tlsx",
    "TLSX",
    "tech",
    ["subdomains", "ips", "urls", "mixed"],
    "subdomains",
    "TLS certificate grabbing",
    2,
    "bg-indigo-500/15",
    "text-indigo-400",
    "border-indigo-500/30",
    Eye,
  ),
  M(
    "wafw00f",
    "Wafw00f",
    "tech",
    ["urls", "subdomains", "mixed"],
    "urls",
    "Web Application Firewall detection",
    2,
    "bg-indigo-500/15",
    "text-indigo-400",
    "border-indigo-500/30",
    Eye,
  ),
];

// Map module weight (1..5) + workflow min/max → concrete instance count
function computeFleetSize(weight: number, min: number, max: number): number {
  const lo = Math.max(1, Math.min(min, max));
  const hi = Math.max(lo, max);
  const t = Math.max(0, Math.min(1, (weight - 1) / 4));
  return Math.round(lo + (hi - lo) * t);
}

// ─── Tree helpers (DAG fan-out) ──────────────────────────────────────────────
// Steps form a directed acyclic graph. A step's `parentIds` lists its
// upstream dependencies; with 2+ entries the step is a join (waits for ALL
// parents and consumes their merged + deduped outputs).
// For tree-style display we treat `parentIds[0]` as the "primary parent".
// Returns steps whose PRIMARY parent matches `parentId` — used by the tree
// renderer so each step shows up in exactly one place.
function getChildSteps<S extends { id: string; parentIds?: string[] }>(
  steps: S[],
  parentId: string | null,
): S[] {
  return steps.filter((s) => (s.parentIds?.[0] ?? null) === parentId);
}
function getDescendantIds<S extends { id: string; parentIds?: string[] }>(
  steps: S[],
  rootId: string,
): Set<string> {
  const out = new Set<string>();
  const stack: string[] = [rootId];
  while (stack.length) {
    const id = stack.pop()!;
    for (const s of steps) {
      if ((s.parentIds ?? []).includes(id) && !out.has(s.id)) {
        out.add(s.id);
        stack.push(s.id);
      }
    }
  }
  return out;
}
function getParentStep<S extends { id: string; parentIds?: string[] }>(
  steps: S[],
  step: S,
): S | undefined {
  const pid = step.parentIds?.[0];
  return pid ? steps.find((s) => s.id === pid) : undefined;
}

const moduleByName = (name: string) =>
  MODULE_CATALOG.find((m) => m.name === name);

// ─── Workflow templates ───────────────────────────────────────────────────────

const WORKFLOW_TEMPLATES: WorkflowTemplate[] = [
  {
    id: "ip-basic",
    name: "IP Recon",
    description: "Port scan → HTTP probe → vuln scan",
    inputType: "ips",
    steps: [{ module: "naabu" }, { module: "httpx" }, { module: "nuclei" }],
    tags: ["ports", "http", "vulns"],
    difficulty: "easy",
  },
  {
    id: "ip-deep",
    name: "Deep IP Scan",
    description: "Fast discovery → detailed nmap → HTTP → screenshots → nuclei",
    inputType: "ips",
    steps: [
      { module: "masscan" },
      { module: "nmap" },
      { module: "httpx" },
      { module: "gowitness" },
      { module: "nuclei" },
    ],
    tags: ["ports", "http", "screenshots", "vulns"],
    difficulty: "advanced",
  },
  {
    id: "domain-quick",
    name: "Quick Domain Recon",
    description: "Subdomain enum → HTTP probe → vuln scan",
    inputType: "domains",
    steps: [{ module: "subfinder" }, { module: "httpx" }, { module: "nuclei" }],
    tags: ["subdomains", "http", "vulns"],
    difficulty: "easy",
  },
  {
    id: "domain-full",
    name: "Full Domain Recon",
    description: "Enum → DNS → HTTP → ports → screenshots → vulns",
    inputType: "domains",
    steps: [
      { module: "subfinder" },
      { module: "dnsx" },
      { module: "httpx" },
      { module: "naabu" },
      { module: "gowitness" },
      { module: "nuclei" },
    ],
    tags: ["subdomains", "dns", "ports", "screenshots", "vulns"],
    difficulty: "medium",
  },
  {
    id: "domain-bugbounty",
    name: "Bug Bounty",
    description:
      "Amass + Subfinder → DNS → HTTP → historical URLs → nuclei + ffuf",
    inputType: "domains",
    steps: [
      { module: "amass" },
      { module: "subfinder" },
      { module: "dnsx" },
      { module: "httpx" },
      { module: "gau" },
      { module: "nuclei" },
      { module: "ffuf" },
    ],
    tags: ["subdomains", "dns", "urls", "vulns", "fuzz"],
    difficulty: "advanced",
  },
  {
    id: "subdomain-probe",
    name: "Subdomain Probe",
    description: "DNS resolve → HTTP → port scan → nuclei",
    inputType: "subdomains",
    steps: [
      { module: "dnsx" },
      { module: "httpx" },
      { module: "naabu" },
      { module: "nuclei" },
    ],
    tags: ["dns", "http", "ports", "vulns"],
    difficulty: "easy",
  },
  {
    id: "url-audit",
    name: "URL Audit",
    description: "Crawl → WAF detect → directory fuzz → nuclei",
    inputType: "urls",
    steps: [
      { module: "katana" },
      { module: "wafw00f" },
      { module: "ffuf" },
      { module: "nuclei" },
    ],
    tags: ["urls", "fuzz", "tech", "vulns"],
    difficulty: "medium",
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function uid() {
  return Math.random().toString(36).slice(2, 9);
}

// ─── Persistence (localStorage) ──────────────────────────────────────────────
// Workflow runs only live in React state, so a page refresh used to wipe both
// the live "run" tab and the "history" tab. We mirror them into localStorage,
// serialising Date objects to ISO strings and modules to their `name` (since
// React component references can't survive JSON).
const WF_STORAGE_KEYS = {
  activeRun: "axwf:activeRun:v1",
  pastRuns: "axwf:pastRuns:v1",
  customTemplates: "axwf:customTemplates:v1",
} as const;

// User-saved workflow templates. Persisted as plain JSON (module names only,
// like the built-in WORKFLOW_TEMPLATES) so they survive a page refresh.
function loadCustomTemplates(): WorkflowTemplate[] {
  try {
    const raw = localStorage.getItem(WF_STORAGE_KEYS.customTemplates);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (t) => t && typeof t.id === "string" && Array.isArray(t.steps),
    ) as WorkflowTemplate[];
  } catch {
    return [];
  }
}

function saveCustomTemplates(templates: WorkflowTemplate[]): void {
  try {
    localStorage.setItem(
      WF_STORAGE_KEYS.customTemplates,
      JSON.stringify(templates),
    );
  } catch {
    // storage full / unavailable — non-fatal, templates just won't persist
  }
}

function serializeStep(s: ExecutingStep): any {
  return {
    id: s.id,
    moduleName: s.module.name,
    customArgs: s.customArgs,
    enabled: s.enabled,
    fleetSize: s.fleetSize,
    parentIds: s.parentIds,
    status: s.status,
    scanId: s.scanId,
    startTime: s.startTime ? s.startTime.toISOString() : undefined,
    endTime: s.endTime ? s.endTime.toISOString() : undefined,
    resultCount: s.resultCount,
    outputLines: s.outputLines,
    error: s.error,
  };
}
function deserializeStep(raw: any): ExecutingStep | null {
  const m = moduleByName(raw.moduleName ?? raw.module);
  if (!m) return null;
  // Back-compat: older runs stored `parentId` (single string).
  const parentIds: string[] | undefined = Array.isArray(raw.parentIds)
    ? raw.parentIds
    : raw.parentId
      ? [raw.parentId]
      : undefined;
  return {
    id: raw.id,
    module: m,
    customArgs: raw.customArgs ?? "",
    enabled: raw.enabled !== false,
    fleetSize: raw.fleetSize,
    parentIds,
    status: raw.status ?? "pending",
    scanId: raw.scanId,
    startTime: raw.startTime ? new Date(raw.startTime) : undefined,
    endTime: raw.endTime ? new Date(raw.endTime) : undefined,
    resultCount: raw.resultCount,
    outputLines: raw.outputLines,
    error: raw.error,
  };
}
/** Safely convert any value to a Date, or return undefined for invalid/missing. */
function toDate(v: any): Date | undefined {
  if (!v) return undefined;
  if (v instanceof Date) return isNaN(v.getTime()) ? undefined : v;
  const d = new Date(v);
  return isNaN(d.getTime()) ? undefined : d;
}

function serializeRun(run: WorkflowRun): any {
  return {
    id: run.id,
    name: run.name,
    inputType: run.inputType,
    initialTargets: run.initialTargets,
    status: run.status,
    currentStepIndex: run.currentStepIndex,
    startTime: run.startTime?.toISOString(),
    endTime: run.endTime?.toISOString(),
    steps: run.steps.map(serializeStep),
  };
}
function deserializeRun(raw: any): WorkflowRun | null {
  try {
    if (!raw || !Array.isArray(raw.steps)) return null;
    const steps = raw.steps
      .map(deserializeStep)
      .filter((s: any) => s !== null) as ExecutingStep[];
    return {
      id: raw.id,
      name: raw.name,
      inputType: raw.inputType,
      initialTargets: raw.initialTargets ?? [],
      status: raw.status ?? "completed",
      currentStepIndex: raw.currentStepIndex ?? 0,
      startTime: toDate(raw.startTime),
      endTime: toDate(raw.endTime),
      steps,
    };
  } catch {
    return null;
  }
}
function loadActiveRunFromStorage(): WorkflowRun | null {
  try {
    const raw = localStorage.getItem(WF_STORAGE_KEYS.activeRun);
    if (!raw) return null;
    return deserializeRun(JSON.parse(raw));
  } catch {
    return null;
  }
}
function saveActiveRunToStorage(run: WorkflowRun | null) {
  try {
    if (run)
      localStorage.setItem(
        WF_STORAGE_KEYS.activeRun,
        JSON.stringify(serializeRun(run)),
      );
    else localStorage.removeItem(WF_STORAGE_KEYS.activeRun);
  } catch {
    /* quota or disabled storage — silently ignore */
  }
}
function loadPastRunsFromStorage(): WorkflowRun[] {
  try {
    const raw = localStorage.getItem(WF_STORAGE_KEYS.pastRuns);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.map(deserializeRun).filter(Boolean) as WorkflowRun[];
  } catch {
    return [];
  }
}
function savePastRunsToStorage(runs: WorkflowRun[]) {
  try {
    localStorage.setItem(
      WF_STORAGE_KEYS.pastRuns,
      JSON.stringify(runs.map(serializeRun)),
    );
  } catch {
    /* ignore */
  }
}

// Parse a scan name like "wf-myworkflow-abc123-httpx" into its parts.
// Returns null when it isn't a workflow scan. Exported via export so other
// components (e.g. ActiveScans) can use it.
export function parseWorkflowScanName(
  name: string,
): { workflowName: string; stepId: string; moduleName: string } | null {
  if (!name || !name.startsWith("wf-")) return null;
  const parts = name.split("-");
  if (parts.length < 4) return null;
  const moduleName = parts[parts.length - 1];
  const stepId = parts[parts.length - 2];
  const workflowName = parts.slice(1, -2).join("-");
  if (!workflowName || !stepId || !moduleName) return null;
  return { workflowName, stepId, moduleName };
}

const INPUT_TYPE_META: Record<
  InputType,
  {
    label: string;
    example: string;
    Icon: React.ComponentType<{ className?: string }>;
    solid: string;
    bg: string;
    border: string;
    text: string;
  }
> = {
  ips: {
    label: "IP Addresses",
    example: "192.168.1.1\n10.0.0.0/24\n172.16.0.1",
    Icon: Cpu,
    solid: "bg-orange-500",
    bg: "bg-orange-500/10",
    border: "border-orange-500/40",
    text: "text-orange-400",
  },
  domains: {
    label: "Domains",
    example: "example.com\ntarget.io\nhackerone.com",
    Icon: Globe,
    solid: "bg-cyan-500",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/40",
    text: "text-cyan-400",
  },
  subdomains: {
    label: "Subdomains",
    example: "api.example.com\ndev.target.io\nstage.app.com",
    Icon: Network,
    solid: "bg-blue-500",
    bg: "bg-blue-500/10",
    border: "border-blue-500/40",
    text: "text-blue-400",
  },
  urls: {
    label: "URLs",
    example: "https://example.com\nhttp://api.target.io/v1",
    Icon: Link2,
    solid: "bg-emerald-500",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/40",
    text: "text-emerald-400",
  },
  mixed: {
    label: "Mixed",
    example: "192.168.1.1\nexample.com\nsub.target.io",
    Icon: Shuffle,
    solid: "bg-purple-500",
    bg: "bg-purple-500/10",
    border: "border-purple-500/40",
    text: "text-purple-400",
  },
};

const DIFF_META = {
  easy: {
    label: "Easy",
    cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  },
  medium: {
    label: "Medium",
    cls: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  },
  advanced: {
    label: "Advanced",
    cls: "text-red-400 bg-red-500/10 border-red-500/30",
  },
};

const CATEGORY_META: Record<
  ModuleInfo["category"],
  { label: string; color: string }
> = {
  enum: { label: "Subdomain Enum", color: "text-cyan-400" },
  dns: { label: "DNS", color: "text-blue-400" },
  port: { label: "Port Scan", color: "text-orange-400" },
  http: { label: "HTTP Probe", color: "text-emerald-400" },
  vuln: { label: "Vulnerability", color: "text-red-400" },
  screenshot: { label: "Screenshots", color: "text-purple-400" },
  fuzz: { label: "Fuzzing", color: "text-pink-400" },
  url: { label: "URL Discovery", color: "text-yellow-400" },
  tech: { label: "Tech Detection", color: "text-indigo-400" },
};

function detectInputType(raw: string): InputType {
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) return "mixed";
  let ips = 0,
    domains = 0,
    subdomains = 0,
    urls = 0;
  const ipRe = /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/;
  const urlRe = /^https?:\/\//i;
  const subRe = /^[a-z0-9-]+(\.[a-z0-9-]+){2,}/i;
  const domRe = /^[a-z0-9-]+\.[a-z]{2,}/i;
  lines.forEach((l) => {
    if (urlRe.test(l)) urls++;
    else if (ipRe.test(l)) ips++;
    else if (subRe.test(l)) subdomains++;
    else if (domRe.test(l)) domains++;
  });
  const max = Math.max(ips, domains, subdomains, urls);
  if (max === 0) return "mixed";
  if (max === ips) return "ips";
  if (max === urls) return "urls";
  if (max === subdomains) return "subdomains";
  return "domains";
}

function extractOutput(target: any, outputType: InputType): string[] {
  if (!target) return [];
  switch (outputType) {
    case "subdomains":
      return (target.subdomains ?? [])
        .map((s: any) => s.hostname)
        .filter(Boolean);
    case "ips":
      return (target.subdomains ?? [])
        .map((s: any) => s.ip)
        .filter(Boolean)
        .filter(
          (ip: string, i: number, arr: string[]) => arr.indexOf(ip) === i,
        );
    case "urls":
      return (target.subdomains ?? [])
        .map((s: any) => s.url ?? (s.hostname ? `http://${s.hostname}` : null))
        .filter(Boolean);
    default:
      return (target.subdomains ?? [])
        .map((s: any) => s.hostname)
        .filter(Boolean);
  }
}

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: StepStatus | WorkflowStatus }) {
  const cfg = {
    pending: {
      cls: "text-white-400 bg-zinc-800 border-zinc-700",
      Icon: Clock,
      label: "Pending",
    },
    running: {
      cls: "text-cyan-300 bg-cyan-500/15 border-cyan-500/40 animate-pulse",
      Icon: Activity,
      label: "Running",
    },
    completed: {
      cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/40",
      Icon: CheckCircle2,
      label: "Done",
    },
    failed: {
      cls: "text-red-400 bg-red-500/10 border-red-500/40",
      Icon: XCircle,
      label: "Failed",
    },
    skipped: {
      cls: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
      Icon: AlertTriangle,
      label: "Skipped",
    },
    idle: {
      cls: "text-white-400 bg-zinc-800 border-zinc-700",
      Icon: Clock,
      label: "Idle",
    },
    aborted: {
      cls: "text-orange-400 bg-orange-500/10 border-orange-500/40",
      Icon: StopCircle,
      label: "Aborted",
    },
  } as const;
  const c = cfg[status as keyof typeof cfg] ?? cfg.pending;
  const Icon = c.Icon;
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-semibold ${c.cls}`}
    >
      <Icon className="w-3 h-3" />
      {c.label}
    </span>
  );
}

// ─── Module picker modal ──────────────────────────────────────────────────────

function ModulePicker({
  open,
  onClose,
  onSelect,
  filterInputType,
  placementHint,
  provisioner,
}: {
  open: boolean;
  onClose: () => void;
  onSelect: (m: ModuleInfo) => void;
  filterInputType: InputType;
  placementHint?: string;
  /** Auto-detected axiom fleet provisioner/image (e.g. "default", "reconftw") — "unknown" disables image filtering. */
  provisioner?: string;
}) {
  const [search, setSearch] = useState("");
  const [filterCat, setFilterCat] = useState<ModuleInfo["category"] | "all">(
    "all",
  );
  const prov = provisioner ?? "unknown";

  const compatibleModules = MODULE_CATALOG.filter(
    (m) =>
      filterInputType === "mixed" ||
      m.accepts.includes(filterInputType) ||
      m.accepts.includes("mixed"),
  );

  const filtered = MODULE_CATALOG.filter((m) => {
    if (filterCat !== "all" && m.category !== filterCat) return false;
    if (
      filterInputType !== "mixed" &&
      !m.accepts.includes(filterInputType) &&
      !m.accepts.includes("mixed")
    )
      return false;
    if (
      search &&
      !m.name.includes(search.toLowerCase()) &&
      !m.label.toLowerCase().includes(search.toLowerCase()) &&
      !m.description.toLowerCase().includes(search.toLowerCase())
    )
      return false;
    return true;
  }).sort((a, b) => {
    // Modules installed on the detected fleet image sort first.
    const aAvail = isModuleAvailable(a.name, prov) ? 0 : 1;
    const bAvail = isModuleAvailable(b.name, prov) ? 0 : 1;
    return aAvail - bAvail;
  });

  const categories = Array.from(
    new Set(MODULE_CATALOG.map((m) => m.category)),
  ) as ModuleInfo["category"][];

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-dark-800 border border-dark-600 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl ring-1 ring-white/5">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
          <div>
            <h3 className="text-sm font-bold text-white">Add a scan module</h3>
            {placementHint && (
              <p className="text-[11px] text-primary-300 mt-0.5 font-mono">
                {placementHint}
              </p>
            )}
            <p className="text-[12px] text-white-500 mt-0.5">
              Showing tools compatible with{" "}
              <span
                className={`font-semibold ${INPUT_TYPE_META[filterInputType].text}`}
              >
                {INPUT_TYPE_META[filterInputType].label}
              </span>{" "}
              input
            </p>
            {prov !== "unknown" && (
              <p className="text-[11px] text-cyan-400/80 mt-0.5">
                Fleet image:{" "}
                <span className="font-semibold">
                  {PROVISIONER_LABELS[prov] ?? prov}
                </span>{" "}
                — tools not installed on it are greyed out
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-white-400 hover:text-white hover:bg-dark-700 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Search */}
        <div className="px-4 pt-3 pb-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white-500 pointer-events-none" />
            <input
              autoFocus
              type="text"
              placeholder="Search tools…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-dark-900 border border-dark-600 rounded-xl pl-9 pr-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-primary-500/60 focus:ring-1 focus:ring-primary-500/20"
            />
          </div>
        </div>

        {/* Category chips */}
        <div className="px-4 pb-2.5 flex gap-1.5 flex-wrap">
          <button
            onClick={() => setFilterCat("all")}
            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold transition-colors border ${filterCat === "all" ? "bg-primary-500/20 text-primary-300 border-primary-500/40" : "bg-dark-700 text-white-400 border-dark-600 hover:text-white"}`}
          >
            All ({compatibleModules.length})
          </button>
          {categories.map((cat) => {
            const count = MODULE_CATALOG.filter(
              (m) =>
                m.category === cat &&
                (filterInputType === "mixed" ||
                  m.accepts.includes(filterInputType) ||
                  m.accepts.includes("mixed")),
            ).length;
            if (count === 0) return null;
            return (
              <button
                key={cat}
                onClick={() => setFilterCat(cat)}
                className={`px-2.5 py-1 rounded-full text-[11px] font-semibold transition-colors border ${filterCat === cat ? `bg-dark-600 border-dark-500 ${CATEGORY_META[cat].color}` : "bg-dark-700 text-white-500 border-dark-600 hover:text-white-200"}`}
              >
                {CATEGORY_META[cat].label}
              </button>
            );
          })}
        </div>

        {/* Module grid */}
        <div className="flex-1 overflow-y-auto px-4 pb-4 grid grid-cols-1 sm:grid-cols-2 gap-2">
          {filtered.length === 0 && (
            <div className="col-span-2 py-12 text-center text-white-500">
              <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p className="text-sm">No tools match</p>
            </div>
          )}
          {filtered.map((m) => {
            const Icon = m.Icon;
            const compatible =
              m.accepts.includes(filterInputType) ||
              m.accepts.includes("mixed") ||
              filterInputType === "mixed";
            const available = isModuleAvailable(m.name, prov);
            const neededImages = !available
              ? getRequiredProvisioners(m.name)
              : [];
            return (
              <button
                key={m.name}
                onClick={() => {
                  onSelect(m);
                  onClose();
                }}
                title={
                  !available
                    ? neededImages.length > 0
                      ? `Not installed on the ${PROVISIONER_LABELS[prov] ?? prov} image — available on: ${neededImages.join(", ")}`
                      : `Not installed on the ${PROVISIONER_LABELS[prov] ?? prov} image`
                    : undefined
                }
                className={`group flex items-start gap-3 text-left p-3.5 rounded-xl border transition-all hover:scale-[1.01] active:scale-[0.99] ${compatible ? `${m.borderClass} hover:border-opacity-80` : "border-dark-600 opacity-60 hover:opacity-80"} ${m.colorClass} ${!available ? "opacity-50" : ""}`}
              >
                <div
                  className={`p-2 rounded-lg ${m.colorClass} border ${m.borderClass} flex-shrink-0`}
                >
                  <Icon className={`w-4 h-4 ${m.textClass}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className={`text-sm font-bold ${m.textClass}`}>
                      {m.label}
                    </span>
                    {!compatible && (
                      <span className="text-[9px] text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 px-1.5 py-0.5 rounded-full font-semibold">
                        type mismatch
                      </span>
                    )}
                    {!available && (
                      <span className="text-[9px] text-white-500 bg-dark-700 border border-dark-600 px-1.5 py-0.5 rounded-full font-semibold">
                        not in {PROVISIONER_LABELS[prov] ?? prov} image
                      </span>
                    )}
                  </div>
                  <p className="text-[12px] text-white-400 leading-snug">
                    {m.description}
                  </p>
                  <div className="flex items-center gap-1.5 mt-1.5">
                    <span className="text-[10px] text-white-600">outputs</span>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold border ${INPUT_TYPE_META[m.outputType]?.bg} ${INPUT_TYPE_META[m.outputType]?.text} ${INPUT_TYPE_META[m.outputType]?.border}`}
                    >
                      {INPUT_TYPE_META[m.outputType]?.label}
                    </span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─── Step card ────────────────────────────────────────────────────────────────

function StepCard({
  step,
  index,
  total,
  onRemove,
  onMoveUp,
  onMoveDown,
  onToggle,
  onArgsChange,
  onFleetSizeChange,
  onAddChild,
  onAddSibling,
  prevOutputType,
  isExecuting,
  execStep,
  minInstances,
  maxInstances,
  joinParentLabels,
}: {
  step: BuilderStep;
  index: number;
  total: number;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onToggle: () => void;
  onArgsChange: (v: string) => void;
  onFleetSizeChange?: (v: number | undefined) => void;
  onAddChild?: () => void;
  onAddSibling?: () => void;
  prevOutputType: InputType;
  isExecuting?: boolean;
  execStep?: ExecutingStep;
  minInstances?: number;
  maxInstances?: number;
  /** Module labels of all parents — only set & rendered when this step is a join (parentIds.length > 1). */
  joinParentLabels?: string[];
}) {
  const [showArgs, setShowArgs] = useState(false);
  const { module: m } = step;
  const Icon = m.Icon;
  const mismatch =
    !m.accepts.includes(prevOutputType) && !m.accepts.includes("mixed");
  const status = execStep?.status ?? "pending";
  const isRunningNow = status === "running";
  const isDone = status === "completed";
  const isFailed = status === "failed";

  return (
    <div
      className={`relative rounded-xl border transition-all duration-200 ${
        !step.enabled
          ? "border-dark-700 bg-dark-800/40 opacity-50"
          : isRunningNow
            ? `${m.borderClass} ${m.colorClass} ring-2 ring-offset-2 ring-offset-dark-900 ring-cyan-500/30`
            : isDone
              ? "border-emerald-500/30 bg-emerald-500/5"
              : isFailed
                ? "border-red-500/30 bg-red-500/5"
                : `${m.borderClass} ${m.colorClass}`
      }`}
    >
      <div className="flex items-stretch">
        {/* Step number column */}
        <div
          className={`w-10 flex-shrink-0 flex items-center justify-center rounded-l-xl border-r ${!step.enabled ? "border-dark-700 bg-dark-800/60" : `${m.borderClass} ${m.colorClass}`}`}
        >
          <span
            className={`text-xs font-bold font-mono ${!step.enabled ? "text-white-600" : m.textClass}`}
          >
            {String(index + 1).padStart(2, "0")}
          </span>
        </div>

        <div className="flex-1 p-3 min-w-0">
          <div className="flex items-start gap-2.5">
            {/* Module icon */}
            <div
              className={`p-1.5 rounded-lg border flex-shrink-0 mt-0.5 ${m.colorClass} ${m.borderClass}`}
            >
              <Icon className={`w-4 h-4 ${m.textClass}`} />
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-0.5">
                <span
                  className={`text-sm font-bold ${m.textClass} ${!step.enabled ? "line-through opacity-60" : ""}`}
                >
                  {m.label}
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-semibold border ${m.colorClass} ${m.textClass} ${m.borderClass}`}
                >
                  {CATEGORY_META[m.category].label}
                </span>
                {mismatch && !isExecuting && (
                  <span className="text-[10px] text-yellow-300 bg-yellow-500/10 border border-yellow-500/30 px-1.5 py-0.5 rounded-full font-semibold flex items-center gap-1">
                    <AlertTriangle className="w-2.5 h-2.5" />
                    type mismatch
                  </span>
                )}
                {joinParentLabels && joinParentLabels.length > 1 && (
                  <span
                    title={`Waits for all ${joinParentLabels.length} upstream branches to finish, then runs once on the merged + deduped output: ${joinParentLabels.join(", ")}`}
                    className="text-[10px] text-primary-300 bg-primary-500/10 border border-primary-500/30 px-1.5 py-0.5 rounded-full font-semibold flex items-center gap-1"
                  >
                    <GitBranch className="w-2.5 h-2.5" />
                    joins {joinParentLabels.length}:{" "}
                    {joinParentLabels.join(" + ")}
                  </span>
                )}
                {isExecuting && <StatusBadge status={status} />}
              </div>

              <p className="text-[12px] text-white-400">{m.description}</p>

              {/* Type flow arrow */}
              <div className="flex items-center gap-1.5 mt-1.5">
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold border ${INPUT_TYPE_META[prevOutputType]?.bg} ${INPUT_TYPE_META[prevOutputType]?.text} ${INPUT_TYPE_META[prevOutputType]?.border}`}
                >
                  {INPUT_TYPE_META[prevOutputType]?.label}
                </span>
                <ArrowRight className="w-3 h-3 text-white-600 flex-shrink-0" />
                <Icon className={`w-3 h-3 ${m.textClass} flex-shrink-0`} />
                <ArrowRight className="w-3 h-3 text-white-600 flex-shrink-0" />
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold border ${INPUT_TYPE_META[m.outputType]?.bg} ${INPUT_TYPE_META[m.outputType]?.text} ${INPUT_TYPE_META[m.outputType]?.border}`}
                >
                  {INPUT_TYPE_META[m.outputType]?.label}
                </span>
              </div>

              {/* Execution stats */}
              {isExecuting && execStep && (
                <div className="mt-2 flex flex-wrap gap-2 text-[11px] font-mono">
                  {execStep.resultCount !== undefined && (
                    <span className="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/30">
                      {execStep.resultCount.toLocaleString()} results
                    </span>
                  )}
                  {execStep.scanId && (
                    <span className="text-white-500 truncate max-w-[200px]">
                      {execStep.scanId}
                    </span>
                  )}
                  {execStep.error && (
                    <span className="text-red-400 truncate max-w-[300px] bg-red-500/10 px-2 py-0.5 rounded-full border border-red-500/30">
                      {execStep.error}
                    </span>
                  )}
                  {execStep.startTime instanceof Date &&
                    execStep.endTime instanceof Date && (
                      <span className="text-white-500">
                        {Math.round(
                          (execStep.endTime.getTime() -
                            execStep.startTime.getTime()) /
                            1000,
                        )}
                        s
                      </span>
                    )}
                </div>
              )}

              {/* Custom args + fleet size */}
              {!isExecuting && (
                <>
                  <div className="mt-1.5 flex items-center gap-3 flex-wrap">
                    <button
                      onClick={() => setShowArgs((v) => !v)}
                      className="flex items-center gap-1 text-[11px] text-white-600 hover:text-white-300 font-mono transition-colors"
                    >
                      <Terminal className="w-3 h-3" />
                      {showArgs ? "hide" : "custom args"}
                      {step.customArgs && !showArgs && (
                        <span className="text-primary-400 ml-1 truncate max-w-[200px]">
                          {step.customArgs}
                        </span>
                      )}
                    </button>
                    {onFleetSizeChange && (
                      <div className="flex items-center gap-1.5 text-[11px] text-white-600 font-mono">
                        <Server className="w-3 h-3" />
                        <span>instances:</span>
                        <input
                          type="number"
                          min={1}
                          value={step.fleetSize ?? ""}
                          placeholder={String(
                            computeFleetSize(
                              step.module.weight,
                              minInstances ?? 1,
                              maxInstances ?? 5,
                            ),
                          )}
                          onChange={(e) => {
                            const raw = e.target.value.trim();
                            if (raw === "") onFleetSizeChange(undefined);
                            else {
                              const n = parseInt(raw, 10);
                              if (!Number.isNaN(n) && n > 0)
                                onFleetSizeChange(n);
                            }
                          }}
                          className="w-14 bg-dark-900 border border-dark-600 rounded-md px-1.5 py-0.5 text-[11px] text-white font-mono placeholder-zinc-700 focus:outline-none focus:border-primary-500/60"
                          title={`Module weight ${step.module.weight}/5 — default scales between workflow min/max instances`}
                        />
                        <span className="text-white-700">
                          (w{step.module.weight})
                        </span>
                      </div>
                    )}
                  </div>
                  {showArgs && (
                    <input
                      type="text"
                      value={step.customArgs}
                      onChange={(e) => onArgsChange(e.target.value)}
                      placeholder="e.g. -t 100 --rate 1000 -silent"
                      className="mt-1.5 w-full bg-dark-900 border border-dark-600 rounded-lg px-2.5 py-1.5 text-xs text-white font-mono placeholder-zinc-600 focus:outline-none focus:border-primary-500/60"
                    />
                  )}
                </>
              )}
            </div>

            {/* Controls (builder only) */}
            {!isExecuting && (
              <div className="flex flex-col gap-0.5 flex-shrink-0 pt-0.5">
                <button
                  onClick={onToggle}
                  title={step.enabled ? "Disable" : "Enable"}
                  className={`p-1.5 rounded-lg transition-colors ${step.enabled ? "text-emerald-400 hover:bg-emerald-500/10" : "text-white-600 hover:text-white-400"}`}
                >
                  {step.enabled ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5" />
                  )}
                </button>
                {onAddChild && (
                  <button
                    onClick={onAddChild}
                    title="Add next step — runs sequentially, taking this step's output as its input"
                    className="p-1.5 rounded-lg text-white-500 hover:text-emerald-400 hover:bg-emerald-500/10 transition-colors"
                  >
                    <CornerDownRight className="w-3.5 h-3.5" />
                  </button>
                )}
                {onAddSibling && (
                  <button
                    onClick={onAddSibling}
                    title="Add parallel step — runs alongside this one, off the same upstream input"
                    className="p-1.5 rounded-lg text-white-500 hover:text-primary-400 hover:bg-primary-500/10 transition-colors"
                  >
                    <GitBranch className="w-3.5 h-3.5" />
                  </button>
                )}
                <button
                  onClick={onMoveUp}
                  disabled={index === 0}
                  title="Move up among siblings"
                  className="p-1.5 rounded-lg text-white-500 hover:text-white hover:bg-dark-700 disabled:opacity-20 transition-colors"
                >
                  <ChevronUp className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={onMoveDown}
                  disabled={index === total - 1}
                  title="Move down among siblings"
                  className="p-1.5 rounded-lg text-white-500 hover:text-white hover:bg-dark-700 disabled:opacity-20 transition-colors"
                >
                  <ChevronDown className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={onRemove}
                  title="Remove this step and its branches"
                  className="p-1.5 rounded-lg text-white-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Recursive tree renderer ─────────────────────────────────────────────────
// Renders a forest of steps. Roots are steps with no parentId; children sit
// indented underneath their parent. Used for both the builder and the live run
// view. Siblings (same parent) execute in parallel at runtime.

interface StepTreeProps {
  steps: BuilderStep[];
  parentId: string | null;
  depth: number;
  initialInputType: InputType;
  isExecuting?: boolean;
  // builder-only callbacks (id-based)
  onRemove?: (id: string) => void;
  onMove?: (id: string, dir: -1 | 1) => void;
  onToggle?: (id: string) => void;
  onArgsChange?: (id: string, val: string) => void;
  onFleetSizeChange?: (id: string, val: number | undefined) => void;
  /** Add a sequential child of the step (uses step.id as parentId for the new step). */
  onAddChild?: (parentId: string) => void;
  /** Add a parallel sibling of the step (uses step.parentId for the new step). */
  onAddSibling?: (siblingId: string) => void;
  /** Add a convergence step downstream of the listed parents (fan-in). */
  onAddJoin?: (parentIds: string[]) => void;
  minInstances?: number;
  maxInstances?: number;
  // exec-only
  getExecStep?: (id: string) => ExecutingStep | undefined;
}

function StepTree(props: StepTreeProps) {
  const {
    steps,
    parentId,
    depth,
    initialInputType,
    isExecuting,
    onRemove,
    onMove,
    onToggle,
    onArgsChange,
    onFleetSizeChange,
    onAddChild,
    onAddSibling,
    onAddJoin,
    minInstances,
    maxInstances,
    getExecStep,
  } = props;

  const siblings = getChildSteps(steps, parentId);
  if (siblings.length === 0) return null;

  const parent = parentId ? steps.find((s) => s.id === parentId) : undefined;
  const prevType: InputType = parent
    ? parent.module.outputType
    : initialInputType;
  const isFanOut = siblings.length > 1;
  const enabledSiblingIds = siblings.filter((s) => s.enabled).map((s) => s.id);

  return (
    <div className={depth > 0 ? "ml-6 pl-3 border-l-2 border-dark-600" : ""}>
      {isFanOut && (
        <div className="flex items-center gap-1.5 mt-1 mb-0.5 text-[10px] font-mono text-primary-400/80">
          <GitBranch className="w-2.5 h-2.5" />
          <span>{siblings.length} parallel branches</span>
        </div>
      )}
      {siblings.map((step, idx) => {
        const execStep = getExecStep?.(step.id);
        const isJoin = (step.parentIds?.length ?? 0) > 1;
        const joinLabels = isJoin
          ? (step.parentIds ?? [])
              .map((pid) => steps.find((s) => s.id === pid)?.module.label)
              .filter(
                Boolean as unknown as (v: string | undefined) => v is string,
              )
          : undefined;
        return (
          <React.Fragment key={step.id}>
            <div className="flex items-stretch gap-3 py-0.5">
              <div
                className={`w-[3px] ml-5 rounded-full ${
                  execStep?.status === "completed"
                    ? "bg-emerald-500/60"
                    : execStep?.status === "running"
                      ? "bg-cyan-500/60"
                      : execStep?.status === "failed"
                        ? "bg-red-500/60"
                        : "bg-dark-600"
                }`}
              />
            </div>
            <StepCard
              step={step}
              index={idx}
              total={siblings.length}
              onRemove={() => onRemove?.(step.id)}
              onMoveUp={() => onMove?.(step.id, -1)}
              onMoveDown={() => onMove?.(step.id, 1)}
              onToggle={() => onToggle?.(step.id)}
              onArgsChange={(v) => onArgsChange?.(step.id, v)}
              onFleetSizeChange={
                onFleetSizeChange
                  ? (v) => onFleetSizeChange(step.id, v)
                  : undefined
              }
              onAddChild={
                !isExecuting && onAddChild
                  ? () => onAddChild(step.id)
                  : undefined
              }
              onAddSibling={
                !isExecuting && onAddSibling
                  ? () => onAddSibling(step.id)
                  : undefined
              }
              prevOutputType={prevType}
              isExecuting={isExecuting}
              execStep={execStep}
              minInstances={minInstances}
              maxInstances={maxInstances}
              joinParentLabels={joinLabels}
            />
            {/* live output preview when executing */}
            {isExecuting &&
              execStep?.status === "completed" &&
              execStep.outputLines &&
              execStep.outputLines.length > 0 && (
                <div className="ml-10 pl-3 border-l-2 border-emerald-500/20 mt-1 mb-1">
                  <div className="text-[11px] text-emerald-400/70 font-mono bg-emerald-500/5 border border-emerald-500/15 rounded-lg px-3 py-2 max-h-20 overflow-y-auto">
                    {execStep.outputLines.slice(0, 6).map((l, i) => (
                      <div key={i} className="truncate">
                        {l}
                      </div>
                    ))}
                    {execStep.outputLines.length > 6 && (
                      <div className="text-emerald-600">
                        …{execStep.outputLines.length - 6} more
                      </div>
                    )}
                  </div>
                </div>
              )}
            {/* recurse into this step's children */}
            <StepTree {...props} parentId={step.id} depth={depth + 1} />
          </React.Fragment>
        );
      })}
      {!isExecuting &&
        isFanOut &&
        onAddJoin &&
        enabledSiblingIds.length > 1 && (
          <button
            onClick={() => onAddJoin(enabledSiblingIds)}
            className="mt-1 ml-5 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border-2 border-dashed border-primary-500/30 text-[11px] font-semibold text-primary-300 hover:bg-primary-500/10 hover:border-primary-500/50 transition-colors"
            title={`Add a step that runs once after ALL ${enabledSiblingIds.length} branches complete, on their merged output`}
          >
            <GitBranch className="w-3 h-3" />
            Add convergence step (after all {enabledSiblingIds.length} branches)
          </button>
        )}
    </div>
  );
}

// ─── Compact DAG preview (used by the Ready-to-launch modal) ────────────────
// Shows the actual execution shape: linear chains stay on one row,
// fan-outs split into stacked sub-trees so parallel branches are obvious.

function PipelinePreview({
  steps,
  inputMeta,
}: {
  steps: BuilderStep[];
  inputMeta: { bg: string; border: string; text: string; label: string };
}) {
  const enabledRoots = getChildSteps(steps, null).filter((s) => s.enabled);
  return (
    <div className="space-y-1">
      <div>
        <span
          className={`inline-block text-[10px] px-2 py-1 rounded-lg border font-semibold ${inputMeta.bg} ${inputMeta.border} ${inputMeta.text}`}
        >
          {inputMeta.label} input
        </span>
      </div>
      <PreviewBranches steps={steps} parentId={null} depth={0} />
    </div>
  );
}

function PreviewBranches({
  steps,
  parentId,
  depth,
}: {
  steps: BuilderStep[];
  parentId: string | null;
  depth: number;
}) {
  const kids = getChildSteps(steps, parentId).filter((s) => s.enabled);
  if (!kids.length) return null;
  const isFanOut = kids.length > 1;
  return (
    <div
      className={
        depth === 0 ? "" : "ml-3 pl-2.5 border-l-2 border-primary-500/30"
      }
    >
      {isFanOut && (
        <div className="flex items-center gap-1 text-[9px] text-primary-400/80 font-mono uppercase tracking-wider py-0.5">
          <GitBranch className="w-2.5 h-2.5" />
          {kids.length} parallel branches
        </div>
      )}
      {kids.map((k) => (
        <PreviewChain
          key={k.id}
          steps={steps}
          start={k}
          depth={depth}
          isParallel={isFanOut}
        />
      ))}
    </div>
  );
}

// Walks a single-child chain inline (a → b → c) until it hits a leaf or a
// fan-out, then recurses into PreviewBranches for the fan-out children.
function PreviewChain({
  steps,
  start,
  depth,
  isParallel,
}: {
  steps: BuilderStep[];
  start: BuilderStep;
  depth: number;
  isParallel: boolean;
}) {
  const chain: BuilderStep[] = [start];
  let curr = start;
  while (true) {
    const nextKids = getChildSteps(steps, curr.id).filter((s) => s.enabled);
    if (nextKids.length !== 1) break;
    chain.push(nextKids[0]);
    curr = nextKids[0];
  }
  return (
    <div className="py-0.5">
      <div className="flex flex-wrap gap-1.5 items-center">
        {isParallel && (
          <ChevronRight className="w-3 h-3 text-primary-500/70 flex-shrink-0" />
        )}
        {chain.map((s, i) => {
          const SIcon = s.module.Icon;
          const isJoin = (s.parentIds?.length ?? 0) > 1;
          return (
            <React.Fragment key={s.id}>
              {i > 0 && (
                <ChevronRight className="w-3 h-3 text-white-600 flex-shrink-0" />
              )}
              {isJoin && (
                <span
                  title={`Waits for all ${s.parentIds!.length} upstream branches before running`}
                  className="text-[9px] px-1.5 py-1 rounded-lg border font-semibold inline-flex items-center gap-1 bg-primary-500/15 border-primary-500/40 text-primary-300"
                >
                  <GitBranch className="w-2.5 h-2.5" />
                  joins {s.parentIds!.length}
                </span>
              )}
              <span
                className={`text-[10px] px-2 py-1 rounded-lg border font-semibold inline-flex items-center gap-1 ${s.module.colorClass} ${s.module.textClass} ${s.module.borderClass}`}
              >
                <SIcon className="w-2.5 h-2.5" />
                {s.module.label}
              </span>
            </React.Fragment>
          );
        })}
      </div>
      {/* recurse into the tail's children (will short-circuit if leaf) */}
      <PreviewBranches steps={steps} parentId={curr.id} depth={depth + 1} />
    </div>
  );
}

// ─── Execution engine hook ────────────────────────────────────────────────────

function useWorkflowExecution(apiUrl: string) {
  // Hydrate from localStorage so the Run tab survives a page refresh.
  // If we find a run still flagged "running", mark it as aborted with a clear
  // reason — the execute() loop died with the previous page, even though the
  // scans it launched are still progressing on the fleet (see Active Scans).
  const [run, setRun] = useState<WorkflowRun | null>(() => {
    const hydrated = loadActiveRunFromStorage();
    if (!hydrated) return null;
    if (hydrated.status === "running") {
      const steps = hydrated.steps.map((s) =>
        s.status === "running" || s.status === "pending"
          ? {
              ...s,
              status:
                s.status === "running"
                  ? ("failed" as StepStatus)
                  : ("skipped" as StepStatus),
              error:
                s.status === "running"
                  ? "page was refreshed — scan may still be running on the fleet (see Active Scans)"
                  : s.error,
              endTime: s.endTime ?? new Date(),
            }
          : s,
      );
      return {
        ...hydrated,
        steps,
        status: "aborted",
        endTime: hydrated.endTime ?? new Date(),
      };
    }
    return hydrated;
  });
  const abortRef = useRef(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Mirror every run state change into localStorage.
  useEffect(() => {
    saveActiveRunToStorage(run);
  }, [run]);

  const backendRunIdRef = useRef<string | null>(null);

  const abort = useCallback(() => {
    abortRef.current = true;
    if (pollRef.current) clearInterval(pollRef.current);
    // Tell the backend runner to stop too
    if (backendRunIdRef.current) {
      fetch(`${apiUrl}/api/workflow/${backendRunIdRef.current}/abort`, {
        method: "POST",
      }).catch(() => {});
    }
    setRun((prev) =>
      prev ? { ...prev, status: "aborted", endTime: new Date() } : prev,
    );
  }, [apiUrl]);

  const reset = useCallback(() => {
    abortRef.current = false;
    if (pollRef.current) clearInterval(pollRef.current);
    setRun(null);
    saveActiveRunToStorage(null);
  }, []);

  // ── Backend-driven execute ─────────────────────────────────────────────────
  // Submits the whole workflow to POST /api/workflow/run (Python runner), then
  // polls GET /api/workflow/{runId}/status every 4 s and mirrors step states
  // into local React state so the UI updates in real time.

  const execute = useCallback(
    async (
      workflowName: string,
      inputType: InputType,
      initialTargets: string[],
      steps: BuilderStep[],
      fleetPrefix?: string,
      minInstances: number = 1,
      maxInstances: number = 5,
      autoTerminateFleet: boolean = false,
    ) => {
      abortRef.current = false;
      const localRunId = uid();
      const execSteps: ExecutingStep[] = steps.map((s) => ({
        ...s,
        status: s.enabled
          ? ("pending" as StepStatus)
          : ("skipped" as StepStatus),
      }));
      setRun({
        id: localRunId,
        name: workflowName,
        inputType,
        initialTargets,
        steps: execSteps,
        status: "running",
        startTime: new Date(),
        currentStepIndex: 0,
      });

      // Serialise the workflow for the Python runner
      const payload = {
        name: workflowName,
        inputType,
        initialTargets,
        steps: steps.map((s) => ({
          id: s.id,
          enabled: s.enabled,
          parentIds: s.parentIds ?? [],
          customArgs: s.customArgs,
          module: {
            name: s.module.name,
            label: s.module.label,
            outputType: s.module.outputType,
            weight: s.module.weight,
          },
          fleetSize: s.fleetSize,
        })),
        config: { fleetPrefix, minInstances, maxInstances, autoTerminateFleet },
      };

      let backendRunId: string;
      try {
        const res = await fetch(`${apiUrl}/api/workflow/run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.error ?? `HTTP ${res.status}`);
        }
        const launched = await res.json();
        backendRunId = launched.runId;
        backendRunIdRef.current = backendRunId;
        console.log(
          `[workflow] backend run started: ${backendRunId}`,
          launched,
        );
      } catch (err: any) {
        setRun((prev) =>
          prev ? { ...prev, status: "failed", endTime: new Date() } : prev,
        );
        console.error("[workflow] failed to start backend run:", err);
        return;
      }

      // Poll /api/workflow/{backendRunId}/status until terminal state
      const POLL_MS = 4_000;
      const TIMEOUT_MS = 60 * 60 * 1000; // 60 min
      const startedAt = Date.now();

      const stopPoll = () => {
        if (pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      };

      const poll = async () => {
        if (abortRef.current) {
          stopPoll();
          return;
        }
        if (Date.now() - startedAt > TIMEOUT_MS) {
          stopPoll();
          setRun((prev) =>
            prev ? { ...prev, status: "failed", endTime: new Date() } : prev,
          );
          return;
        }

        try {
          const res = await fetch(
            `${apiUrl}/api/workflow/${backendRunId}/status`,
          );
          if (!res.ok) return; // transient — keep polling
          const data = await res.json();

          // Determine terminal state BEFORE entering the state updater so we
          // can call stopPoll() as a plain side-effect (not inside setRun).
          const wfStatus: string = data.status ?? "running";
          const isTerminal = ["completed", "failed", "aborted"].includes(
            wfStatus,
          );
          if (isTerminal) stopPoll();

          // Mirror each step's backend status into React state
          setRun((prev) => {
            if (!prev) return prev;
            const updated = prev.steps.map((s) => {
              const bs = data.steps?.[s.id];
              if (!bs) return s;
              const status: StepStatus =
                bs.status === "completed"
                  ? "completed"
                  : bs.status === "failed"
                    ? "failed"
                    : bs.status === "skipped"
                      ? "skipped"
                      : bs.status === "running"
                        ? "running"
                        : s.status;
              return {
                ...s,
                status,
                scanId: bs.scanId ?? s.scanId,
                resultCount: bs.resultCount ?? s.resultCount,
                error: bs.error ?? s.error,
                startTime: toDate(bs.startedAt) ?? s.startTime,
                endTime: toDate(bs.endedAt) ?? s.endTime,
              };
            });

            return {
              ...prev,
              steps: updated,
              status: isTerminal
                ? (wfStatus as WorkflowRun["status"])
                : "running",
              endTime: isTerminal ? new Date() : prev.endTime,
            };
          });
        } catch (_e) {
          // network blip — keep polling
        }
      };

      poll(); // immediate first check
      pollRef.current = setInterval(poll, POLL_MS);
    },
    [apiUrl],
  );

  // ── Legacy helpers kept for reference — no longer called by execute ────────
  const _waitForScan = useCallback(
    (scanId: string, timeoutMs: number = 30 * 60 * 1000): Promise<any> => {
      return new Promise((resolve, reject) => {
        const startedAt = Date.now();
        const stop = () => {
          if (pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
        };
        let seenOnce = false; // becomes true once we've seen the scan in the API at least once

        const check = async () => {
          if (abortRef.current) {
            stop();
            reject(new Error("aborted"));
            return;
          }
          if (Date.now() - startedAt > timeoutMs) {
            stop();
            reject(
              new Error(
                `Scan timed out after ${Math.round(timeoutMs / 60000)} min — check axiom-bridge logs`,
              ),
            );
            return;
          }
          try {
            const res = await fetch(`${apiUrl}/api/axiom/scans`);
            if (!res.ok) return;
            const scans: any[] = await res.json();
            // Match by id, name, or fuzzy substring (handles bridge-generated module+timestamp ids vs. our scan name)
            const scan = scans.find(
              (s) =>
                s.id === scanId ||
                s.name === scanId ||
                (s.id &&
                  scanId &&
                  (s.id.includes(scanId) || scanId.includes(s.id))) ||
                (s.name &&
                  scanId &&
                  (s.name.includes(scanId) || scanId.includes(s.name))),
            );
            if (!scan) return;
            seenOnce = true;
            const status = (scan.status || "").toLowerCase();
            if (
              status === "completed" ||
              status === "done" ||
              status === "finished" ||
              status === "success"
            ) {
              stop();
              resolve(scan);
            } else if (
              status === "failed" ||
              status === "error" ||
              status === "aborted"
            ) {
              stop();
              reject(
                new Error(
                  scan.failure_reason || scan.error || `scan ${status}`,
                ),
              );
            }
            // "running" / "launched" / "initializing" — keep polling
          } catch (_e) {
            // network blip — keep trying
          }
        };
        check();
        pollRef.current = setInterval(check, 8000);
        // suppress unused warning; seenOnce reserved for future heuristics (e.g. forgive transient disappearance)
        void seenOnce;
      });
    },
    [apiUrl],
  );

  const extractScanOutput = useCallback(
    async (
      scanName: string,
      outputType: InputType,
      retries = 12,
    ): Promise<string[]> => {
      for (let i = 0; i < retries; i++) {
        await new Promise((r) => setTimeout(r, 5000));
        if (abortRef.current) return [];
        try {
          const res = await fetch(`${apiUrl}/api/targets`);
          if (!res.ok) continue;
          const targets: any[] = await res.json();
          const target = targets.find(
            (t) =>
              t.id?.toLowerCase().includes(scanName.toLowerCase()) ||
              t.programName?.toLowerCase().includes(scanName.toLowerCase()) ||
              t.sources?.some((s: string) =>
                s.toLowerCase().includes(scanName.toLowerCase()),
              ),
          );
          if (target) {
            const lines = extractOutput(target, outputType);
            if (lines.length > 0) return lines;
          }
        } catch (_e) {}
      }
      return [];
    },
    [apiUrl],
  );

  return { run, execute, abort, reset, backendRunIdRef };
}

// ─── Main component ───────────────────────────────────────────────────────────

interface WorkflowBuilderProps {
  apiUrl: string;
}

export default function WorkflowBuilder({ apiUrl }: WorkflowBuilderProps) {
  const [activeTab, setActiveTab] = useState<"build" | "run" | "history">(
    () => {
      try {
        const t = localStorage.getItem("axwf:activeTab:v1");
        return t === "run" || t === "history" || t === "build" ? t : "build";
      } catch {
        return "build";
      }
    },
  );
  useEffect(() => {
    try {
      localStorage.setItem("axwf:activeTab:v1", activeTab);
    } catch {
      /* ignore */
    }
  }, [activeTab]);
  const [inputType, setInputType] = useState<InputType>("domains");
  const [targets, setTargets] = useState("");
  const [workflowName, setWorkflowName] = useState("");
  const [steps, setSteps] = useState<BuilderStep[]>([]);
  const [showModulePicker, setShowModulePicker] = useState(false);
  // Upstream parents the next-added step will attach to.
  //  - []  → root (consumes initial workflow targets)
  //  - [x] → sequential after step x
  //  - [a, b, c] → join / convergence: waits for all of a,b,c and merges their output
  const [pendingParentIds, setPendingParentIds] = useState<string[]>([]);
  // Label shown in the picker header so the user knows where the new step lands.
  const [pickerHint, setPickerHint] = useState<string>("");
  const [showRunModal, setShowRunModal] = useState(false);
  const [runFleetPrefix, setRunFleetPrefix] = useState("");
  const [minInstances, setMinInstances] = useState("1");
  const [maxInstances, setMaxInstances] = useState("5");
  const [autoTerminateFleet, setAutoTerminateFleet] = useState(false);

  // Team context
  const [teams, setTeams] = useState<{ id: string; name: string }[]>([]);
  const [selectedTeamId, setSelectedTeamId] = useState<string>("");

  // Fleet image (axiom provisioner) — drives module-availability filtering
  // in the picker so users aren't offered tools the current AMI doesn't have.
  const [detectedProvisioner, setDetectedProvisioner] =
    useState<string>("unknown");
  useEffect(() => {
    const fetchProvisioner = async () => {
      try {
        const res = await fetch(`${apiUrl}/api/axiom/config`);
        if (res.ok) {
          const data = await res.json();
          setDetectedProvisioner((data.provisioner || "unknown").toLowerCase());
        }
      } catch {
        // bridge unreachable — leave unfiltered ("unknown")
      }
    };
    fetchProvisioner();
  }, [apiUrl]);

  const [pastRuns, setPastRuns] = useState<WorkflowRun[]>(() =>
    loadPastRunsFromStorage(),
  );
  const [selectedPastRun, setSelectedPastRun] = useState<WorkflowRun | null>(
    null,
  );

  // Mirror past runs into localStorage so the History tab survives refresh.
  useEffect(() => {
    savePastRunsToStorage(pastRuns);
  }, [pastRuns]);

  // User-saved workflow templates (persisted to localStorage).
  const [customTemplates, setCustomTemplates] = useState<WorkflowTemplate[]>(
    () => loadCustomTemplates(),
  );
  useEffect(() => {
    saveCustomTemplates(customTemplates);
  }, [customTemplates]);

  // "Save as template" modal.
  const [showSaveTemplate, setShowSaveTemplate] = useState(false);
  const [saveTplName, setSaveTplName] = useState("");
  const [saveTplDesc, setSaveTplDesc] = useState("");

  const { run, execute, abort, reset, backendRunIdRef } =
    useWorkflowExecution(apiUrl);

  // Fetch teams the current user belongs to (newest first)
  useEffect(() => {
    const loadTeams = async () => {
      try {
        const [meRes, teamsRes] = await Promise.all([
          fetch(`${apiUrl.replace(/\/api.*/, "")}/api/users/me`, {
            credentials: "include",
          }),
          fetch(`${apiUrl.replace(/\/api.*/, "")}/api/teams`, {
            credentials: "include",
          }),
        ]);
        if (meRes.ok && teamsRes.ok) {
          const me = await meRes.json();
          const all: { id: string; name: string; createdAt: string }[] =
            await teamsRes.json();
          const myTeams = all
            .filter((t) => me.teams?.includes(t.id))
            .sort(
              (a, b) =>
                new Date(b.createdAt).getTime() -
                new Date(a.createdAt).getTime(),
            );
          setTeams(myTeams);
          if (myTeams.length > 0) setSelectedTeamId(myTeams[0].id);
        }
      } catch {
        // backend may not support teams yet
      }
    };
    loadTeams();
  }, [apiUrl]);

  const handleTargetsChange = (val: string) => {
    setTargets(val);
    if (val.trim()) setInputType(detectInputType(val));
  };

  const loadTemplate = (tpl: WorkflowTemplate) => {
    // Resolve modules first, dropping any the catalog no longer knows about.
    const resolved = tpl.steps
      .map((s) => ({ s, m: moduleByName(s.module) }))
      .filter((x) => x.m) as Array<{
      s: WorkflowTemplate["steps"][number];
      m: ModuleInfo;
    }>;

    // Fresh id per step, plus a map from the template's saved localId → new id
    // so parent links survive the round-trip.
    const newIds = resolved.map(() => uid());
    const localToNew = new Map<string, string>();
    resolved.forEach((x, i) => {
      if (x.s.localId) localToNew.set(x.s.localId, newIds[i]);
    });

    // Custom templates carry their exact DAG (even all-parallel-roots), so we
    // remap their saved parent links verbatim. Built-in templates store only a
    // flat module list, so we chain each step onto the previous one.
    const preserveStructure = Boolean(tpl.custom);

    const builtSteps: BuilderStep[] = resolved.map((x, i) => {
      let parentIds: string[] | undefined;
      if (preserveStructure) {
        // Custom template — remap saved parent localIds to the new step ids.
        parentIds = (x.s.parentLocalIds ?? [])
          .map((lid) => localToNew.get(lid))
          .filter((id): id is string => Boolean(id));
        if (parentIds.length === 0) parentIds = undefined;
      } else {
        // Built-in linear template — chain each step onto the previous one.
        parentIds = i === 0 ? undefined : [newIds[i - 1]];
      }
      return {
        id: newIds[i],
        module: x.m,
        customArgs: x.s.customArgs ?? "",
        enabled: true,
        fleetSize: x.s.fleetSize,
        parentIds,
      };
    });

    setSteps(builtSteps);
    setInputType(tpl.inputType);
    if (!workflowName) setWorkflowName(tpl.name);
  };

  // Snapshot the current pipeline into a reusable custom template.
  const saveCurrentAsTemplate = (name: string, description: string) => {
    if (steps.length === 0) return;
    const cats: string[] = Array.from(
      new Set(steps.map((s) => s.module.category as string)),
    );
    const difficulty: WorkflowTemplate["difficulty"] =
      steps.length <= 3 ? "easy" : steps.length <= 5 ? "medium" : "advanced";
    const tpl: WorkflowTemplate = {
      id: `custom-${uid()}`,
      name: name.trim() || workflowName.trim() || "Untitled template",
      description:
        description.trim() ||
        steps.map((s) => s.module.label).join(" → "),
      inputType,
      // Preserve full branch structure: localId = builder step id,
      // parentLocalIds = builder parentIds (loadTemplate remaps both).
      steps: steps.map((s) => ({
        module: s.module.name,
        customArgs: s.customArgs || undefined,
        localId: s.id,
        parentLocalIds: s.parentIds,
        fleetSize: s.fleetSize,
      })),
      tags: cats,
      difficulty,
      custom: true,
      createdAt: new Date().toISOString(),
    };
    setCustomTemplates((prev) => [tpl, ...prev]);
    setShowSaveTemplate(false);
    setSaveTplName("");
    setSaveTplDesc("");
  };

  const deleteCustomTemplate = (id: string) => {
    setCustomTemplates((prev) => prev.filter((t) => t.id !== id));
  };

  const addModule = (m: ModuleInfo) => {
    const step: BuilderStep = {
      id: uid(),
      module: m,
      customArgs: "",
      enabled: true,
      parentIds:
        pendingParentIds.length > 0 ? [...pendingParentIds] : undefined,
    };
    setSteps((prev) => [...prev, step]);
    setPendingParentIds([]);
    setPickerHint("");
  };

  const openRootPicker = () => {
    setPendingParentIds([]);
    setPickerHint(
      steps.length === 0
        ? "→ first step (runs on workflow input)"
        : "→ new root branch (parallel with existing root steps)",
    );
    setShowModulePicker(true);
  };
  // Sequential add: new step becomes a CHILD of the given step (consumes its output)
  const openChildPicker = (parentId: string) => {
    const parent = steps.find((s) => s.id === parentId);
    setPendingParentIds([parentId]);
    setPickerHint(
      parent
        ? `→ next step after ${parent.module.label} (sequential)`
        : "→ next step",
    );
    setShowModulePicker(true);
  };
  // Parallel add: new step becomes a SIBLING of the given step
  // (shares the same primary parent, i.e. fans out from the same upstream input)
  const openSiblingPicker = (siblingId: string) => {
    const sib = steps.find((s) => s.id === siblingId);
    const sibParent = sib?.parentIds?.[0] ?? null;
    setPendingParentIds(sibParent ? [sibParent] : []);
    const upstream = sibParent
      ? steps.find((s) => s.id === sibParent)?.module.label
      : "workflow input";
    setPickerHint(
      sib
        ? `→ parallel with ${sib.module.label} (both run off ${upstream})`
        : "→ parallel branch",
    );
    setShowModulePicker(true);
  };
  // Convergence add: new step waits for ALL given parents and consumes the
  // merged + deduped union of their outputs.
  const openJoinPicker = (parentIds: string[]) => {
    const parents = parentIds
      .map((id) => steps.find((s) => s.id === id))
      .filter(Boolean) as BuilderStep[];
    if (parents.length === 0) return;
    setPendingParentIds(parents.map((p) => p.id));
    const labels = parents.map((p) => p.module.label).join(" + ");
    setPickerHint(
      `→ convergence step — runs once after all ${parents.length} branches finish (${labels})`,
    );
    setShowModulePicker(true);
  };

  // Remove a step AND all its descendants. Also strip the removed ids from any
  // surviving step's parentIds so joins don't end up pointing at ghosts.
  const removeStep = (id: string) =>
    setSteps((prev) => {
      const toRemove = getDescendantIds(prev, id);
      toRemove.add(id);
      return prev
        .filter((s) => !toRemove.has(s.id))
        .map((s) => {
          if (!s.parentIds || s.parentIds.length === 0) return s;
          const cleaned = s.parentIds.filter((pid) => !toRemove.has(pid));
          if (cleaned.length === s.parentIds.length) return s;
          return {
            ...s,
            parentIds: cleaned.length > 0 ? cleaned : undefined,
          };
        });
    });
  // Move a step within its sibling group (same primary parent). Up/down only
  // reorders siblings, never changes parent linkage.
  const moveStep = (id: string, dir: -1 | 1) =>
    setSteps((prev) => {
      const target = prev.find((s) => s.id === id);
      if (!target) return prev;
      const targetPP = target.parentIds?.[0] ?? null;
      const siblings = prev.filter(
        (s) => (s.parentIds?.[0] ?? null) === targetPP,
      );
      const sIdx = siblings.findIndex((s) => s.id === id);
      const swap = siblings[sIdx + dir];
      if (!swap) return prev;
      const arr = [...prev];
      const i = arr.findIndex((s) => s.id === id);
      const j = arr.findIndex((s) => s.id === swap.id);
      [arr[i], arr[j]] = [arr[j], arr[i]];
      return arr;
    });
  const toggleStep = (id: string) =>
    setSteps((prev) =>
      prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)),
    );
  const updateArgs = (id: string, val: string) =>
    setSteps((prev) =>
      prev.map((s) => (s.id === id ? { ...s, customArgs: val } : s)),
    );
  const updateFleetSize = (id: string, val: number | undefined) =>
    setSteps((prev) =>
      prev.map((s) => (s.id === id ? { ...s, fleetSize: val } : s)),
    );

  const handleLaunch = async () => {
    const targetLines = targets
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (
      !targetLines.length ||
      !workflowName ||
      !steps.filter((s) => s.enabled).length
    )
      return;
    setShowRunModal(false);
    setActiveTab("run");
    const minN = Math.max(1, parseInt(minInstances || "1", 10) || 1);
    const maxN = Math.max(minN, parseInt(maxInstances || "5", 10) || minN);
    // Prepend team slug if a team is selected
    const teamSlug =
      selectedTeamId && teams.find((t) => t.id === selectedTeamId)
        ? teams
            .find((t) => t.id === selectedTeamId)!
            .name.toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-+|-+$/g, "")
        : "";
    const prefixedName = teamSlug
      ? `${teamSlug}/${workflowName}`
      : workflowName;
    await execute(
      prefixedName,
      inputType,
      targetLines,
      steps,
      runFleetPrefix || undefined,
      minN,
      maxN,
      autoTerminateFleet,
    );
  };

  useEffect(() => {
    if (
      run &&
      (run.status === "completed" ||
        run.status === "failed" ||
        run.status === "aborted")
    ) {
      setPastRuns((prev) => {
        const exists = prev.find((r) => r.id === run.id);
        if (exists) return prev.map((r) => (r.id === run.id ? run : r));
        return [run, ...prev].slice(0, 10);
      });
    }
  }, [run?.status]);

  const canLaunch =
    targets.trim().length > 0 &&
    workflowName.trim().length > 0 &&
    steps.filter((s) => s.enabled).length > 0;
  const isRunning = run?.status === "running";
  const inputMeta = INPUT_TYPE_META[inputType];
  const InputIcon = inputMeta.Icon;
  const targetCount = targets.split("\n").filter((l) => l.trim()).length;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* ── Page header ── */}
      <div className="relative overflow-hidden rounded-xl bg-dark-800 border border-dark-700 p-5">
        <div className="absolute inset-0 bg-gradient-to-br from-primary-500/5 via-transparent to-transparent pointer-events-none" />
        <div className="absolute top-0 right-0 w-64 h-64 bg-primary-500/3 rounded-full -translate-y-1/2 translate-x-1/2 pointer-events-none blur-3xl" />
        <div className="relative flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-primary-500/15 border border-primary-500/30">
              <ScanLine className="w-5 h-5 text-primary-400" />
            </div>
            <div>
              <h1 className="text-base font-bold text-white flex items-center gap-2">
                Workflow Builder
                <span className="text-[10px] font-semibold text-primary-400 bg-primary-500/10 border border-primary-500/30 px-2 py-0.5 rounded-full">
                  BETA
                </span>
              </h1>
              <p className="text-[13px] text-white-400 mt-0.5">
                Chain scans — each step's output automatically feeds the next
              </p>
            </div>
          </div>
          {isRunning && (
            <button
              onClick={abort}
              className="flex items-center gap-2 px-3.5 py-2 bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 rounded-xl text-sm font-semibold transition-colors"
            >
              <StopCircle className="w-4 h-4" />
              Abort
            </button>
          )}
        </div>
      </div>

      {/* ── Tab bar ── */}
      <div className="flex gap-1 bg-dark-800 border border-dark-700 rounded-xl p-1">
        {(["build", "run", "history"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            className={`flex-1 px-4 py-2 rounded-lg text-sm font-semibold transition-all capitalize ${activeTab === t ? "bg-dark-700 text-white shadow-sm" : "text-white-500 hover:text-white-300"}`}
          >
            {t === "run" && run ? (
              <span className="flex items-center justify-center gap-2">
                {t} <StatusBadge status={run.status as any} />
              </span>
            ) : (
              t
            )}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════ BUILD ══════════════════════════════════ */}
      {activeTab === "build" && (
        <div className="space-y-4">
          {/* Input targets */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
            <div className="px-4 py-3 border-b border-dark-700 flex items-center gap-2">
              <div
                className={`w-6 h-6 rounded-lg flex items-center justify-center ${inputMeta.bg} border ${inputMeta.border}`}
              >
                <InputIcon className={`w-3.5 h-3.5 ${inputMeta.text}`} />
              </div>
              <span className="text-sm font-semibold text-white">
                What are you scanning?
              </span>
            </div>
            <div className="p-4 space-y-3">
              {/* Type pills */}
              <div className="flex flex-wrap gap-2">
                {(Object.keys(INPUT_TYPE_META) as InputType[]).map((t) => {
                  const meta = INPUT_TYPE_META[t];
                  const TIcon = meta.Icon;
                  return (
                    <button
                      key={t}
                      onClick={() => setInputType(t)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-semibold transition-all ${
                        inputType === t
                          ? `${meta.bg} ${meta.border} ${meta.text} shadow-sm`
                          : "bg-dark-700/50 border-dark-600 text-white-400 hover:border-dark-500 hover:text-white-200"
                      }`}
                    >
                      <TIcon className="w-3.5 h-3.5" />
                      {meta.label}
                    </button>
                  );
                })}
              </div>

              {/* Textarea */}
              <div className="relative">
                <textarea
                  value={targets}
                  onChange={(e) => handleTargetsChange(e.target.value)}
                  placeholder={`Paste ${inputMeta.label.toLowerCase()} here, one per line\n\n${inputMeta.example}`}
                  rows={5}
                  className={`w-full bg-dark-900 border rounded-xl px-4 py-3 text-sm text-white font-mono placeholder-zinc-700 focus:outline-none resize-none transition-colors ${
                    targetCount > 0
                      ? `${inputMeta.border} focus:${inputMeta.border}`
                      : "border-dark-600 focus:border-primary-500/60"
                  }`}
                />
                {targetCount > 0 && (
                  <div
                    className={`absolute top-2.5 right-3 text-[10px] font-bold px-2 py-0.5 rounded-full ${inputMeta.bg} ${inputMeta.text} border ${inputMeta.border}`}
                  >
                    {targetCount} targets
                  </div>
                )}
              </div>

              {targetCount > 0 && (
                <div
                  className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg ${inputMeta.bg} border ${inputMeta.border}`}
                >
                  <CheckCircle2
                    className={`w-3.5 h-3.5 ${inputMeta.text} flex-shrink-0`}
                  />
                  <span className={inputMeta.text}>
                    Auto-detected as <strong>{inputMeta.label}</strong>
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Templates */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
            <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-white-400" />
                <span className="text-sm font-semibold text-white">
                  Quick-start templates
                </span>
              </div>
              <span className={`text-[11px] font-semibold ${inputMeta.text}`}>
                {inputMeta.label}
              </span>
            </div>
            <div className="p-4">
              {(() => {
                const matches = (t: WorkflowTemplate) =>
                  t.inputType === inputType || inputType === "mixed";
                const visibleTemplates = [
                  ...customTemplates.filter(matches),
                  ...WORKFLOW_TEMPLATES.filter(matches),
                ];
                if (visibleTemplates.length === 0) {
                  return (
                    <p className="text-white-500 text-sm text-center py-4">
                      No templates for this input type — build a custom pipeline
                      below, then save it with{" "}
                      <span className="text-primary-300 font-semibold">
                        Save as template
                      </span>
                      .
                    </p>
                  );
                }
                return (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {visibleTemplates.map((tpl) => {
                      const tplModules = tpl.steps
                        .map((s) => moduleByName(s.module))
                        .filter(Boolean) as ModuleInfo[];
                      const diff = DIFF_META[tpl.difficulty];
                      return (
                        <div
                          key={tpl.id}
                          role="button"
                          tabIndex={0}
                          onClick={() => loadTemplate(tpl)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ")
                              loadTemplate(tpl);
                          }}
                          className="group relative text-left rounded-xl bg-dark-700/40 border border-dark-600 hover:border-primary-500/40 hover:bg-dark-700 transition-all p-0 overflow-hidden cursor-pointer"
                        >
                          <div
                            className={`h-0.5 w-full ${inputMeta.solid} opacity-50 group-hover:opacity-100 transition-opacity`}
                          />
                          {tpl.custom && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteCustomTemplate(tpl.id);
                              }}
                              title="Delete this saved template"
                              className="absolute top-2 right-2 z-10 p-1 rounded-md text-white-500 hover:text-red-400 hover:bg-dark-900/70 transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                          <div className="p-3.5">
                            <div className="flex items-start justify-between gap-2 mb-1">
                              <span className="text-sm font-bold text-white group-hover:text-primary-300 transition-colors leading-tight">
                                {tpl.name}
                              </span>
                              <div className="flex items-center gap-1 flex-shrink-0">
                                {tpl.custom && (
                                  <span className="text-[9px] px-1.5 py-0.5 rounded-full border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 font-bold flex items-center gap-0.5">
                                    <Bookmark className="w-2.5 h-2.5" />
                                    Saved
                                  </span>
                                )}
                                <span
                                  className={`text-[9px] px-1.5 py-0.5 rounded-full border font-bold ${diff.cls} ${tpl.custom ? "mr-5" : ""}`}
                                >
                                  {diff.label}
                                </span>
                              </div>
                            </div>
                            <p className="text-[12px] text-white-400 mb-2.5 leading-snug">
                              {tpl.description}
                            </p>
                            <div className="flex items-center gap-1 flex-wrap">
                              {tplModules.map((m, idx) => {
                                const TIcon = m.Icon;
                                return (
                                  <React.Fragment key={idx}>
                                    <span
                                      className={`text-[10px] px-1.5 py-0.5 rounded-lg ${m.colorClass} ${m.textClass} border ${m.borderClass} font-semibold flex items-center gap-0.5`}
                                    >
                                      <TIcon className="w-2.5 h-2.5" />
                                      {m.label}
                                    </span>
                                    {idx < tplModules.length - 1 && (
                                      <ChevronRight className="w-2.5 h-2.5 text-white-600 flex-shrink-0" />
                                    )}
                                  </React.Fragment>
                                );
                              })}
                            </div>
                            <div className="mt-2.5 pt-2 border-t border-dark-600/60 flex items-center justify-between text-[11px]">
                              <span className="text-white-600">
                                {tpl.steps.length} steps
                              </span>
                              <span className="text-primary-400 group-hover:translate-x-0.5 transition-transform">
                                Use →
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                );
              })()}
            </div>
          </div>

          {/* Pipeline builder */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 overflow-hidden">
            <div className="px-4 py-3 border-b border-dark-700 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-white-400" />
                <span className="text-sm font-semibold text-white">
                  Pipeline
                </span>
                {steps.length > 0 && (
                  <span className="text-[11px] text-white-500">
                    {steps.filter((s) => s.enabled).length} / {steps.length}{" "}
                    active
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {steps.length > 0 && (
                  <button
                    onClick={() => {
                      setSaveTplName(workflowName);
                      setSaveTplDesc("");
                      setShowSaveTemplate(true);
                    }}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-dark-600 bg-dark-700 text-xs text-white-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors"
                  >
                    <Bookmark className="w-3 h-3" />
                    Save as template
                  </button>
                )}
                {steps.length > 0 && (
                  <button
                    onClick={() => setSteps([])}
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-dark-600 bg-dark-700 text-xs text-white-400 hover:text-red-400 hover:border-red-500/30 transition-colors"
                  >
                    <RotateCcw className="w-3 h-3" />
                    Clear
                  </button>
                )}
                <button
                  onClick={openRootPicker}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-primary-500/40 bg-primary-500/10 text-xs font-semibold text-primary-300 hover:bg-primary-500/20 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add step
                </button>
              </div>
            </div>

            <div className="p-4">
              {steps.length === 0 ? (
                <div
                  onClick={openRootPicker}
                  className="py-14 text-center border-2 border-dashed border-dark-600 rounded-xl cursor-pointer hover:border-primary-500/30 transition-all group"
                >
                  <div className="w-12 h-12 rounded-2xl bg-dark-700 border border-dark-600 mx-auto mb-3 flex items-center justify-center group-hover:border-primary-500/40 transition-colors">
                    <Plus className="w-5 h-5 text-white-500 group-hover:text-primary-400 transition-colors" />
                  </div>
                  <p className="text-sm font-semibold text-white-400 group-hover:text-white-300">
                    Build your pipeline
                  </p>
                  <p className="text-xs text-white-600 mt-1">
                    Pick a template above or click to add steps
                  </p>
                </div>
              ) : (
                <div className="space-y-0">
                  {/* Input node */}
                  <div className="mb-1">
                    <div
                      className={`inline-flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-semibold ${inputMeta.bg} ${inputMeta.border} ${inputMeta.text}`}
                    >
                      <InputIcon className="w-3.5 h-3.5" />
                      {targetCount > 0
                        ? `${targetCount} ${inputMeta.label}`
                        : inputMeta.label}
                    </div>
                  </div>

                  <StepTree
                    steps={steps}
                    parentId={null}
                    depth={0}
                    initialInputType={inputType}
                    onRemove={removeStep}
                    onMove={moveStep}
                    onToggle={toggleStep}
                    onArgsChange={updateArgs}
                    onFleetSizeChange={updateFleetSize}
                    onAddChild={openChildPicker}
                    onAddSibling={openSiblingPicker}
                    onAddJoin={openJoinPicker}
                    minInstances={parseInt(minInstances || "1", 10) || 1}
                    maxInstances={parseInt(maxInstances || "5", 10) || 5}
                  />

                  <div className="flex items-stretch gap-3 py-0.5">
                    <div className="w-[3px] ml-5 bg-dark-600 rounded-full" />
                  </div>
                  <button
                    onClick={openRootPicker}
                    className="w-full flex items-center justify-center gap-2 py-3 rounded-xl border-2 border-dashed border-dark-600 text-white-500 hover:border-primary-500/30 hover:text-primary-400 text-xs font-semibold transition-all"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    Append step
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Name & launch */}
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-4 space-y-3">
            {/* Team selector */}
            <div>
              <label className="text-xs font-semibold text-white-400 block mb-1.5">
                Project Team{" "}
                <span className="font-normal text-white-600">(optional)</span>
              </label>
              <select
                value={selectedTeamId}
                onChange={(e) => setSelectedTeamId(e.target.value)}
                className="w-full bg-dark-900 border border-dark-600 rounded-xl px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-primary-500/60"
              >
                <option value="">— No team / personal workflow —</option>
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
              {selectedTeamId &&
                teams.find((t) => t.id === selectedTeamId) &&
                workflowName && (
                  <p className="text-xs text-white-600 font-mono mt-1">
                    Will run as:{" "}
                    <span className="text-primary-400">
                      {teams
                        .find((t) => t.id === selectedTeamId)!
                        .name.toLowerCase()
                        .replace(/[^a-z0-9]+/g, "-")
                        .replace(/^-+|-+$/g, "")}
                      /{workflowName}
                    </span>
                  </p>
                )}
            </div>
            <div className="flex flex-wrap gap-3 items-end">
              <div className="flex-1 min-w-[200px]">
                <label className="text-xs font-semibold text-white-400 block mb-1.5">
                  Workflow name
                </label>
                <input
                  type="text"
                  value={workflowName}
                  onChange={(e) => setWorkflowName(e.target.value)}
                  placeholder="e.g. corp-full-recon-2026"
                  className="w-full bg-dark-900 border border-dark-600 rounded-xl px-3 py-2.5 text-sm text-white font-mono placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 focus:ring-1 focus:ring-primary-500/20"
                />
              </div>
              <button
                disabled={!canLaunch || isRunning}
                onClick={() => setShowRunModal(true)}
                className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-bold transition-all ${
                  canLaunch && !isRunning
                    ? "bg-primary-600 hover:bg-primary-500 text-white shadow-lg shadow-primary-500/20 hover:shadow-primary-500/30 hover:scale-[1.02] active:scale-[0.98]"
                    : "bg-dark-700 text-white-600 cursor-not-allowed border border-dark-600"
                }`}
              >
                <Play className="w-4 h-4" />
                {isRunning ? "Running…" : "Run Workflow"}
              </button>
            </div>
            {!canLaunch && (
              <div className="mt-2.5 flex flex-wrap gap-2">
                {!targets.trim() && (
                  <span className="text-[11px] text-white-500 bg-dark-700 border border-dark-600 px-2.5 py-1 rounded-lg flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3 text-yellow-500" />
                    No targets
                  </span>
                )}
                {!workflowName.trim() && (
                  <span className="text-[11px] text-white-500 bg-dark-700 border border-dark-600 px-2.5 py-1 rounded-lg flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3 text-yellow-500" />
                    No name
                  </span>
                )}
                {targets.trim() &&
                  workflowName.trim() &&
                  steps.filter((s) => s.enabled).length === 0 && (
                    <span className="text-[11px] text-white-500 bg-dark-700 border border-dark-600 px-2.5 py-1 rounded-lg flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-yellow-500" />
                      No active steps
                    </span>
                  )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════ RUN ══════════════════════════════════ */}
      {activeTab === "run" && (
        <div className="space-y-4">
          {!run ? (
            <div className="py-20 text-center">
              <div className="w-14 h-14 rounded-2xl bg-dark-800 border border-dark-700 mx-auto mb-4 flex items-center justify-center">
                <Activity className="w-6 h-6 text-white-600" />
              </div>
              <p className="text-sm font-semibold text-white-400">
                No workflow running yet
              </p>
              <p className="text-xs text-white-600 mt-1">
                Build your pipeline and hit Run Workflow
              </p>
              <button
                onClick={() => setActiveTab("build")}
                className="mt-4 text-primary-400 hover:text-primary-300 text-xs font-semibold transition-colors"
              >
                ← Back to builder
              </button>
            </div>
          ) : (
            <>
              {/* Status bar */}
              <div
                className={`rounded-xl border p-4 ${
                  run.status === "running"
                    ? "border-cyan-500/30 bg-cyan-500/5"
                    : run.status === "completed"
                      ? "border-emerald-500/30 bg-emerald-500/5"
                      : run.status === "failed"
                        ? "border-red-500/30 bg-red-500/5"
                        : run.status === "aborted"
                          ? "border-orange-500/30 bg-orange-500/5"
                          : "border-dark-700 bg-dark-800"
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2.5 mb-1">
                      <span className="text-base font-bold text-white">
                        {run.name}
                      </span>
                      <StatusBadge status={run.status as any} />
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-white-500">
                      <span>
                        {run.initialTargets.length} targets ·{" "}
                        {INPUT_TYPE_META[run.inputType].label}
                      </span>
                      {run.startTime && (
                        <span>
                          Started{" "}
                          {run.startTime instanceof Date
                            ? run.startTime.toLocaleTimeString()
                            : String(run.startTime ?? "")}
                        </span>
                      )}
                      {run.endTime && run.startTime && (
                        <span>
                          {Math.round(
                            ((run.endTime instanceof Date
                              ? run.endTime.getTime()
                              : 0) -
                              (run.startTime instanceof Date
                                ? run.startTime.getTime()
                                : 0)) /
                              1000,
                          )}
                          s total
                        </span>
                      )}
                      {run.status === "running" && (
                        <span>
                          {
                            run.steps.filter((s) => s.status === "running")
                              .length
                          }{" "}
                          running ·{" "}
                          {
                            run.steps.filter((s) => s.status === "completed")
                              .length
                          }{" "}
                          / {run.steps.filter((s) => s.enabled).length} done
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {run.status === "running" && (
                      <button
                        onClick={abort}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 rounded-xl text-xs font-semibold transition-colors"
                      >
                        <StopCircle className="w-3.5 h-3.5" />
                        Abort
                      </button>
                    )}
                    {backendRunIdRef.current && (
                      <a
                        href={`${apiUrl}/api/workflow/${backendRunIdRef.current}/log`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-700 border border-dark-600 text-white-300 hover:text-white rounded-xl text-xs font-semibold transition-colors"
                        title="Open verbose runner log in a new tab"
                      >
                        <FileText className="w-3.5 h-3.5" />
                        Runner log
                      </a>
                    )}
                    {run.status !== "running" && (
                      <button
                        onClick={() => {
                          reset();
                          setActiveTab("build");
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-700 border border-dark-600 text-white-300 hover:text-white rounded-xl text-xs font-semibold transition-colors"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        New workflow
                      </button>
                    )}
                  </div>
                </div>
                {(run.status === "running" || run.status === "completed") && (
                  <div className="mt-3 h-1.5 bg-dark-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${run.status === "completed" ? "bg-emerald-500" : "bg-primary-500"}`}
                      style={{
                        width: `${(run.steps.filter((s) => s.status === "completed" || s.status === "skipped").length / Math.max(run.steps.length, 1)) * 100}%`,
                      }}
                    />
                  </div>
                )}
              </div>

              {/* Live pipeline */}
              <div className="space-y-0">
                <div className="mb-1">
                  <div
                    className={`inline-flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-semibold ${INPUT_TYPE_META[run.inputType].bg} ${INPUT_TYPE_META[run.inputType].border} ${INPUT_TYPE_META[run.inputType].text}`}
                  >
                    {(() => {
                      const IIcon = INPUT_TYPE_META[run.inputType].Icon;
                      return <IIcon className="w-3.5 h-3.5" />;
                    })()}
                    {run.initialTargets.length}{" "}
                    {INPUT_TYPE_META[run.inputType].label}
                    <span className="text-[11px] font-normal opacity-60 ml-1 truncate max-w-[200px]">
                      {run.initialTargets.slice(0, 2).join(", ")}
                      {run.initialTargets.length > 2
                        ? ` +${run.initialTargets.length - 2}`
                        : ""}
                    </span>
                  </div>
                </div>

                {run.steps.map(() => null)}
                <StepTree
                  steps={run.steps}
                  parentId={null}
                  depth={0}
                  initialInputType={run.inputType}
                  isExecuting={true}
                  getExecStep={(id) => run.steps.find((s) => s.id === id)}
                />

                {run.status === "completed" && (
                  <div className="mt-2 flex items-center gap-2 px-4 py-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 text-sm font-bold text-emerald-400">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                    Workflow complete — results imported to Targets
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* ══════════════════════════════════ HISTORY ══════════════════════════════════ */}
      {activeTab === "history" && (
        <div className="space-y-2">
          {pastRuns.length === 0 ? (
            <div className="py-20 text-center">
              <div className="w-14 h-14 rounded-2xl bg-dark-800 border border-dark-700 mx-auto mb-4 flex items-center justify-center">
                <Clock className="w-6 h-6 text-white-600" />
              </div>
              <p className="text-sm font-semibold text-white-400">
                No past runs yet
              </p>
              <p className="text-xs text-white-600 mt-1">
                Completed workflows will appear here
              </p>
            </div>
          ) : (
            pastRuns.map((r) => {
              const rMeta = INPUT_TYPE_META[r.inputType];
              const expanded = selectedPastRun?.id === r.id;
              return (
                <div
                  key={r.id}
                  className="bg-dark-800 rounded-xl border border-dark-700 hover:border-dark-600 overflow-hidden transition-colors cursor-pointer"
                  onClick={() => setSelectedPastRun(expanded ? null : r)}
                >
                  <div className="px-4 py-3 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <StatusBadge status={r.status as any} />
                      <span className="text-sm font-bold text-white truncate">
                        {r.name}
                      </span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold flex-shrink-0 ${rMeta.bg} ${rMeta.border} ${rMeta.text}`}
                      >
                        {rMeta.label}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0 text-xs text-white-500">
                      <span>
                        {r.steps.filter((s) => s.enabled).length} steps
                      </span>
                      {r.startTime && (
                        <span>
                          {r.startTime instanceof Date
                            ? r.startTime.toLocaleDateString()
                            : String(r.startTime ?? "")}
                        </span>
                      )}
                      <ChevronDown
                        className={`w-4 h-4 transition-transform ${expanded ? "rotate-180" : ""}`}
                      />
                    </div>
                  </div>
                  {expanded && (
                    <div className="border-t border-dark-700 px-4 py-3 bg-dark-900/40 space-y-2">
                      {r.steps.map((step) => {
                        const SIcon = step.module.Icon;
                        return (
                          <div
                            key={step.id}
                            className="flex items-center gap-3"
                          >
                            <div
                              className={`p-1.5 rounded-lg ${step.module.colorClass} border ${step.module.borderClass} flex-shrink-0`}
                            >
                              <SIcon
                                className={`w-3 h-3 ${step.module.textClass}`}
                              />
                            </div>
                            <span
                              className={`text-xs font-bold w-24 flex-shrink-0 ${step.module.textClass}`}
                            >
                              {step.module.label}
                            </span>
                            <StatusBadge status={step.status} />
                            {step.resultCount !== undefined && (
                              <span className="text-xs text-emerald-400 font-mono">
                                {step.resultCount.toLocaleString()} results
                              </span>
                            )}
                            {step.error && (
                              <span className="text-xs text-red-400 truncate max-w-xs">
                                {step.error}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Module picker modal */}
      <ModulePicker
        open={showModulePicker}
        onClose={() => {
          setShowModulePicker(false);
          setPendingParentIds([]);
          setPickerHint("");
        }}
        onSelect={addModule}
        placementHint={pickerHint || undefined}
        filterInputType={(() => {
          if (pendingParentIds.length === 0) return inputType;
          const parents = pendingParentIds
            .map((id) => steps.find((s) => s.id === id))
            .filter(Boolean) as BuilderStep[];
          if (parents.length === 0) return inputType;
          const types = new Set(parents.map((p) => p.module.outputType));
          return types.size === 1
            ? (parents[0].module.outputType as InputType)
            : ("mixed" as InputType);
        })()}
        provisioner={detectedProvisioner}
      />

      {/* Save-as-template modal */}
      {showSaveTemplate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-2xl w-full max-w-md shadow-2xl ring-1 ring-white/5 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30">
                  <Bookmark className="w-4 h-4 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">
                    Save as template
                  </h3>
                  <p className="text-[11px] text-white-500 mt-0.5">
                    {steps.length} step{steps.length === 1 ? "" : "s"} ·{" "}
                    {inputMeta.label} input · saved to this browser
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowSaveTemplate(false)}
                className="p-1.5 rounded-lg text-white-400 hover:text-white hover:bg-dark-700 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="block text-[11px] font-semibold text-white-400 mb-1.5 uppercase tracking-wider">
                  Template name
                </label>
                <input
                  autoFocus
                  type="text"
                  value={saveTplName}
                  onChange={(e) => setSaveTplName(e.target.value)}
                  placeholder="e.g. My domain recon"
                  className="w-full bg-dark-900 border border-dark-600 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20"
                />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-white-400 mb-1.5 uppercase tracking-wider">
                  Description{" "}
                  <span className="text-white-600 normal-case font-normal">
                    (optional)
                  </span>
                </label>
                <input
                  type="text"
                  value={saveTplDesc}
                  onChange={(e) => setSaveTplDesc(e.target.value)}
                  placeholder={steps.map((s) => s.module.label).join(" → ")}
                  className="w-full bg-dark-900 border border-dark-600 rounded-xl px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/20"
                />
              </div>
            </div>
            <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-dark-700">
              <button
                onClick={() => setShowSaveTemplate(false)}
                className="px-3 py-2 rounded-xl border border-dark-600 bg-dark-700 text-xs font-semibold text-white-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => saveCurrentAsTemplate(saveTplName, saveTplDesc)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-cyan-500/40 bg-cyan-500/15 text-xs font-bold text-cyan-300 hover:bg-cyan-500/25 transition-colors"
              >
                <Bookmark className="w-3.5 h-3.5" />
                Save template
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Run confirmation modal */}
      {showRunModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-2xl w-full max-w-md shadow-2xl ring-1 ring-white/5 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-primary-500/15 border border-primary-500/30">
                  <Play className="w-4 h-4 text-primary-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">
                    Ready to launch
                  </h3>
                  <p className="text-[11px] text-white-500 mt-0.5">
                    {workflowName}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowRunModal(false)}
                className="p-1.5 rounded-lg text-white-500 hover:text-white hover:bg-dark-700 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* Stats */}
              <div className="grid grid-cols-3 gap-2">
                {[
                  {
                    label: "Targets",
                    value: targets.split("\n").filter((l) => l.trim()).length,
                    color: inputMeta.text,
                  },
                  {
                    label: "Steps",
                    value: steps.filter((s) => s.enabled).length,
                    color: "text-primary-400",
                  },
                  {
                    label: "Type",
                    value: inputMeta.label,
                    color: inputMeta.text,
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="bg-dark-900/60 rounded-xl border border-dark-700 p-3 text-center"
                  >
                    <div className={`text-lg font-bold ${item.color}`}>
                      {item.value}
                    </div>
                    <div className="text-[11px] text-white-500 mt-0.5">
                      {item.label}
                    </div>
                  </div>
                ))}
              </div>

              {/* Pipeline preview */}
              <div>
                <p className="text-[11px] font-semibold text-white-500 mb-2 uppercase tracking-wider">
                  Execution order
                </p>
                <PipelinePreview steps={steps} inputMeta={inputMeta} />
              </div>

              {/* Fleet options */}
              <div>
                <p className="text-[11px] font-semibold text-white-500 mb-2 uppercase tracking-wider">
                  Fleet sizing
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={runFleetPrefix}
                    onChange={(e) => setRunFleetPrefix(e.target.value)}
                    placeholder="Fleet prefix (optional, e.g. recon)"
                    className="flex-1 bg-dark-900 border border-dark-600 rounded-xl px-3 py-2 text-xs text-white font-mono placeholder-zinc-700 focus:outline-none focus:border-primary-500/60"
                  />
                  <div className="flex flex-col">
                    <span className="text-[9px] text-white-600 font-mono uppercase tracking-wider mb-0.5">
                      min
                    </span>
                    <input
                      type="number"
                      value={minInstances}
                      onChange={(e) => setMinInstances(e.target.value)}
                      min={1}
                      className="w-20 bg-dark-900 border border-dark-600 rounded-xl px-3 py-2 text-xs text-white font-mono placeholder-zinc-700 focus:outline-none focus:border-primary-500/60"
                    />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[9px] text-white-600 font-mono uppercase tracking-wider mb-0.5">
                      max
                    </span>
                    <input
                      type="number"
                      value={maxInstances}
                      onChange={(e) => setMaxInstances(e.target.value)}
                      min={1}
                      className="w-20 bg-dark-900 border border-dark-600 rounded-xl px-3 py-2 text-xs text-white font-mono placeholder-zinc-700 focus:outline-none focus:border-primary-500/60"
                    />
                  </div>
                </div>
                <p className="text-[10px] text-white-600 mt-1.5">
                  Light modules use{" "}
                  <span className="text-white-400 font-mono">min</span>, heavy
                  modules use{" "}
                  <span className="text-white-400 font-mono">max</span>. Each
                  step can override on its card (w1=light → w5=demanding).
                </p>
                {/* Auto-terminate toggle */}
                <label className="flex items-center gap-2.5 mt-3 cursor-pointer select-none group">
                  <div
                    onClick={() => setAutoTerminateFleet((v) => !v)}
                    className={`w-8 h-4 rounded-full transition-colors ${
                      autoTerminateFleet ? "bg-primary-500" : "bg-dark-600"
                    }`}
                  >
                    <div
                      className={`w-3 h-3 mt-0.5 rounded-full bg-white shadow transition-transform ${
                        autoTerminateFleet
                          ? "translate-x-4.5"
                          : "translate-x-0.5"
                      }`}
                    />
                  </div>
                  <span className="text-xs text-white-400 group-hover:text-white-200 transition-colors">
                    Auto-terminate idle instances after each step
                  </span>
                </label>
                {autoTerminateFleet && (
                  <p className="text-[10px] text-amber-400/80 mt-1 ml-10.5">
                    Instances are deleted as soon as their step finishes. The
                    next step will spin up fresh ones.
                  </p>
                )}
                {(() => {
                  const minN = Math.max(
                    1,
                    parseInt(minInstances || "1", 10) || 1,
                  );
                  const maxN = Math.max(
                    minN,
                    parseInt(maxInstances || "5", 10) || minN,
                  );
                  const enabled = steps.filter((s) => s.enabled);
                  if (!enabled.length) return null;
                  return (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {enabled.map((s) => {
                        const SIcon = s.module.Icon;
                        const n =
                          s.fleetSize ??
                          computeFleetSize(s.module.weight, minN, maxN);
                        return (
                          <span
                            key={s.id}
                            className={`text-[10px] px-2 py-1 rounded-lg border font-semibold flex items-center gap-1 ${s.module.colorClass} ${s.module.textClass} ${s.module.borderClass}`}
                          >
                            <SIcon className="w-2.5 h-2.5" />
                            {s.module.label}
                            <span className="text-white-300/80 font-mono">
                              ×{n}
                            </span>
                            {s.fleetSize !== undefined && (
                              <span
                                className="text-yellow-300"
                                title="manual override"
                              >
                                *
                              </span>
                            )}
                          </span>
                        );
                      })}
                    </div>
                  );
                })()}
              </div>
            </div>

            <div className="px-5 py-3 border-t border-dark-700 flex gap-2 justify-end bg-dark-900/40">
              <button
                onClick={() => setShowRunModal(false)}
                className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-white-300 hover:text-white rounded-xl text-sm font-semibold transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleLaunch}
                className="px-6 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-sm font-bold transition-all hover:shadow-lg hover:shadow-primary-500/20 flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                Launch
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
