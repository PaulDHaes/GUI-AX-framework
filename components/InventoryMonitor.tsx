import { useState, useEffect, useCallback, useRef } from "react";
import {
  RefreshCw, ChevronDown, ChevronRight, ExternalLink,
  AlertTriangle, ShieldCheck, Shield, BrainCircuit, Settings2, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useActiveProject } from "@/lib/useActiveProject";

const API_BASE = "http://localhost:5000";
const LS_AI   = "inventory_ai_settings";

// ── Types ──────────────────────────────────────────────────────────────────────

interface Cve {
  id: string; published: string; severity: string;
  score: number; description: string; verified: boolean; is_new?: boolean;
}
interface CveV5 {
  kev?: boolean;
  pocRefs?: { url: string; tags: string[]; name?: string }[];
  affected?: { vendor: string; product: string; versions: string[] }[];
  exploitation?: string | null;
}
interface TechEntry {
  product: string; version: string; hostnames: string[]; programs: string[];
  cve_count: number; max_severity: number; cves: Cve[]; last_checked: string;
}
interface BridgeProject { token: string; name: string; client: string; }
interface Inventory {
  last_full_scan: string | null;
  technologies: TechEntry[];
  projects: BridgeProject[];
  linkedScansCount?: number;
}
interface Status {
  running: boolean; last_full_scan: string | null;
  progress: string | null; total_entries: number;
}
interface AiSettings {
  provider: "anthropic" | "openai" | "ollama";
  api_key: string; model: string; base_url: string; chunk_size: number;
}
interface ChunkResult { index: number; total: number; text: string; error?: string; }

const DEFAULT_AI: AiSettings = {
  provider: "anthropic", api_key: "", model: "", base_url: "", chunk_size: 5,
};

const SYSTEM_PROMPT = `You are a senior penetration tester reviewing CVE findings for a security assessment.
For each technology entry, evaluate:
- Exploitability in a pentest context
- CVEs with known public exploits (CVSS >= 7.0 first)
- Quick wins for the assessment
- Flag CVEs marked "unverified" (version match was keyword-based, not CPE-confirmed)
Be concise and practical. Use bullet points. Skip entries with no CVEs.`;

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

function sevColor(sev: string): string {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return "bg-red-600 text-white";
    case "HIGH":     return "bg-orange-500 text-white";
    case "MEDIUM":   return "bg-yellow-500 text-black";
    case "LOW":      return "bg-blue-500 text-white";
    default:         return "bg-muted text-muted-foreground";
  }
}
function sevDot(sev: string): string {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return "text-red-500";
    case "HIGH":     return "text-orange-400";
    case "MEDIUM":   return "text-yellow-400";
    case "LOW":      return "text-blue-400";
    default:         return "text-muted-foreground";
  }
}
function topCve(cves: Cve[]): Cve | null {
  if (!cves.length) return null;
  return cves.reduce((best, c) =>
    (SEV_ORDER[c.severity] ?? 9) < (SEV_ORDER[best.severity] ?? 9) ? c : best);
}
function maxSev(cves: Cve[]): string {
  const top = topCve(cves);
  return top ? top.severity : "NONE";
}
function relTime(iso: string | null): string {
  if (!iso) return "never";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60)    return "just now";
  if (diff < 3600)  return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}
function chunkArray<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
function loadAiSettings(): AiSettings {
  try { return { ...DEFAULT_AI, ...JSON.parse(localStorage.getItem(LS_AI) || "{}") }; }
  catch { return { ...DEFAULT_AI }; }
}
function saveAiSettings(s: AiSettings) { localStorage.setItem(LS_AI, JSON.stringify(s)); }

// Sort CVEs: newest published first; within same date, highest score first
function sortCvesNewestFirst(cves: Cve[]): Cve[] {
  return [...cves].sort((a, b) => {
    const dateDiff = b.published.localeCompare(a.published);
    if (dateDiff !== 0) return dateDiff;
    return b.score - a.score;
  });
}

// ── Vendor-aware CVE lookup links ─────────────────────────────────────────────

const VENDOR_ADVISORIES_INV = [
  { name: "Grafana",       keywords: ["grafana"],                                                                   url: (c: string) => `https://grafana.com/security/security-advisories/?q=${c}` },
  { name: "Microsoft",     keywords: ["microsoft", "windows", "iis", "exchange", "sharepoint", "mssql", "smb", "rdp", "ntlm", "outlook", "defender"], url: (c: string) => `https://msrc.microsoft.com/update-guide/vulnerability/${c}` },
  { name: "Apache",        keywords: ["apache", "httpd", "tomcat", "struts", "log4j", "log4shell", "solr"],         url: () => `https://httpd.apache.org/security/vulnerabilities_24.html` },
  { name: "Nginx",         keywords: ["nginx"],                                                                     url: () => `https://nginx.org/en/security_advisories.html` },
  { name: "OpenSSL",       keywords: ["openssl", "heartbleed", "beast", "poodle", "drown", "logjam"],              url: () => `https://www.openssl.org/news/vulnerabilities.html` },
  { name: "Cisco",         keywords: ["cisco", "ios xe", "asa", "webex", "anyconnect", "firepower"],               url: (c: string) => `https://tools.cisco.com/security/center/search.x?publicationTypeIDs=1&q=${c}` },
  { name: "Fortinet",      keywords: ["fortinet", "fortios", "fortigate", "fortimanager", "fortiweb"],             url: (c: string) => `https://fortiguard.fortinet.com/psirt?name=${c}` },
  { name: "Palo Alto",     keywords: ["palo alto", "panos", "pan-os", "globalprotect"],                            url: (c: string) => `https://security.paloaltonetworks.com/?q=${encodeURIComponent(c)}` },
  { name: "VMware",        keywords: ["vmware", "vsphere", "esxi", "vcenter", "nsx", "horizon"],                   url: () => `https://www.vmware.com/security/advisories.html` },
  { name: "Citrix",        keywords: ["citrix", "netscaler", "xenapp", "adc"],                                     url: (c: string) => `https://support.citrix.com/search#/?q=${c}` },
  { name: "F5",            keywords: ["f5", "big-ip", "bigip", "icontrol", "tmui"],                                url: (c: string) => `https://my.f5.com/manage/s/article/${c}` },
  { name: "Atlassian",     keywords: ["atlassian", "jira", "confluence", "bitbucket"],                             url: (c: string) => `https://jira.atlassian.com/issues/?jql=text+~+"${c}"` },
  { name: "Jenkins",       keywords: ["jenkins"],                                                                   url: () => `https://www.jenkins.io/security/advisories/` },
  { name: "GitLab",        keywords: ["gitlab"],                                                                    url: (c: string) => `https://gitlab.com/gitlab-org/cves/-/issues?search=${c}` },
  { name: "WordPress",     keywords: ["wordpress", "wp-", "woocommerce"],                                          url: (c: string) => `https://wpscan.com/vulnerability/search/?text=${c}` },
  { name: "Linux / RHEL",  keywords: ["linux kernel", "kernel", "ubuntu", "debian", "centos", "rhel", "red hat"],  url: (c: string) => `https://access.redhat.com/security/cve/${c}` },
  { name: "Spring",        keywords: ["spring", "spring boot", "spring framework", "spring security"],             url: () => `https://spring.io/security` },
  { name: "Kubernetes",    keywords: ["kubernetes", "k8s", "containerd", "runc", "docker"],                        url: () => `https://kubernetes.io/docs/reference/issues-security/official-cve-feed/` },
  { name: "Node / npm",    keywords: ["node.js", "nodejs", "npm ", "express", "electron"],                         url: (c: string) => `https://security.snyk.io/search?q=${c}` },
  { name: "Python / pip",  keywords: ["python", "django", "flask", "fastapi", "pypi"],                             url: (c: string) => `https://security.snyk.io/search?q=${c}` },
  { name: "PHP",           keywords: ["php", "laravel", "symfony"],                                                 url: () => `https://www.php.net/security/` },
  { name: "Ivanti",        keywords: ["ivanti", "pulse secure", "mobileiron"],                                     url: () => `https://forums.ivanti.com/s/topic/0TO4d000000KXQUGA4/security-advisories` },
  { name: "Juniper",       keywords: ["juniper", "junos", "srx"],                                                   url: (c: string) => `https://kb.juniper.net/InfoCenter/index?page=content&q=${c}` },
];

function buildInvLookups(cveId: string, description: string) {
  const cveNum = cveId.replace(/^CVE-/i, "");
  const lower = description.toLowerCase();
  const vendor = VENDOR_ADVISORIES_INV.find((v) => v.keywords.some((kw) => lower.includes(kw)));
  return { cveNum, vendor };
}

function CveLookupLinks({ cveId, description }: { cveId: string; description: string }) {
  const [open, setOpen] = useState(false);
  const { cveNum, vendor } = buildInvLookups(cveId, description);

  const groups = [
    {
      label: "DB",
      pill: "bg-blue-500/10 text-blue-400 border-blue-500/25 hover:bg-blue-500/20",
      links: [
        { label: "NVD",       url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
        { label: "MITRE",     url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}` },
        { label: "CISA KEV",  url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}` },
      ],
    },
    {
      label: "Exploit",
      pill: "bg-orange-500/10 text-orange-400 border-orange-500/25 hover:bg-orange-500/20",
      links: [
        { label: "Exploit-DB",  url: `https://www.exploit-db.com/search?cve=${cveNum}` },
        { label: "Metasploit",  url: `https://www.rapid7.com/db/?q=${cveId}&type=metasploit` },
        { label: "AttackerKB",  url: `https://attackerkb.com/search?q=${cveId}` },
        { label: "GitHub PoC",  url: `https://github.com/search?q=${cveId}&type=code&s=stars&o=desc` },
      ],
    },
    ...(vendor ? [{
      label: vendor.name,
      pill: "bg-cyan-500/10 text-cyan-400 border-cyan-500/25 hover:bg-cyan-500/20",
      links: [{ label: vendor.name + " Advisory", url: vendor.url(cveId) }],
    }] : []),
    {
      label: "Research",
      pill: "bg-purple-500/10 text-purple-400 border-purple-500/25 hover:bg-purple-500/20",
      links: [
        { label: "VulDB",       url: `https://vuldb.com/?search.cve=${cveId}` },
        { label: "Snyk",        url: `https://security.snyk.io/search?q=${cveId}` },
        { label: "HackTricks",  url: `https://www.google.com/search?q=${encodeURIComponent(`site:hacktricks.wiki ${cveId}`)}` },
      ],
    },
  ];

  return (
    <div className="mt-2">
      <button
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
        className="text-[10px] font-mono text-muted-foreground/50 hover:text-cyan-400 transition-colors flex items-center gap-1"
      >
        {open ? "▾" : "▸"} research links{vendor ? ` · ${vendor.name} detected` : ""}
      </button>
      {open && (
        <div className="mt-1.5 space-y-1.5">
          {groups.map((g) => (
            <div key={g.label} className="flex flex-wrap gap-1.5 items-center">
              <span className="text-[10px] text-muted-foreground/40 font-mono w-16 flex-shrink-0">{g.label}</span>
              {g.links.map((l) => (
                <a
                  key={l.label}
                  href={l.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border transition-colors ${g.pill}`}
                >
                  {l.label}
                  <ExternalLink className="w-2.5 h-2.5 flex-shrink-0" />
                </a>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── AI Settings Panel ─────────────────────────────────────────────────────────

function AiSettingsPanel({
  settings, onChange, onClose,
}: { settings: AiSettings; onChange: (s: AiSettings) => void; onClose: () => void }) {
  const set = (patch: Partial<AiSettings>) => {
    const next = { ...settings, ...patch };
    onChange(next);
    saveAiSettings(next);
  };
  const placeholders: Record<string, string> = {
    anthropic: "claude-opus-4-8", openai: "gpt-4o", ollama: "llama3",
  };

  return (
    <div className="rounded-lg border border-border/50 bg-secondary/20 p-4 mb-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium text-foreground flex items-center gap-2">
          <Settings2 className="w-4 h-4" /> AI Analysis Settings
        </span>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Provider</label>
          <select
            className="w-full h-8 px-2 rounded-md border border-border bg-background text-sm text-foreground"
            value={settings.provider}
            onChange={e => set({ provider: e.target.value as AiSettings["provider"] })}
          >
            <option value="anthropic">Anthropic (Claude)</option>
            <option value="openai">OpenAI / compatible</option>
            <option value="ollama">Ollama (local)</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-muted-foreground mb-1">Model</label>
          <input
            className="w-full h-8 px-3 rounded-md border border-border bg-background text-sm text-foreground placeholder:text-muted-foreground"
            placeholder={placeholders[settings.provider]}
            value={settings.model}
            onChange={e => set({ model: e.target.value })}
          />
        </div>
        {settings.provider !== "ollama" && (
          <div className="col-span-2">
            <label className="block text-xs text-muted-foreground mb-1">API Key</label>
            <input type="password"
              className="w-full h-8 px-3 rounded-md border border-border bg-background text-sm text-foreground font-mono"
              placeholder="sk-…"
              value={settings.api_key}
              onChange={e => set({ api_key: e.target.value })}
            />
          </div>
        )}
        {(settings.provider === "openai" || settings.provider === "ollama") && (
          <div className="col-span-2">
            <label className="block text-xs text-muted-foreground mb-1">
              Base URL {settings.provider === "ollama" ? "(default: http://localhost:11434)" : "(leave blank for OpenAI)"}
            </label>
            <input
              className="w-full h-8 px-3 rounded-md border border-border bg-background text-sm text-foreground font-mono"
              placeholder={settings.provider === "ollama" ? "http://localhost:11434" : "https://api.openai.com"}
              value={settings.base_url}
              onChange={e => set({ base_url: e.target.value })}
            />
          </div>
        )}
        <div className="col-span-2">
          <label className="block text-xs text-muted-foreground mb-1">
            Entries per chunk: <strong>{settings.chunk_size}</strong>
            <span className="text-muted-foreground/60 ml-2">(smaller = less context per request)</span>
          </label>
          <input type="range" min={1} max={20} step={1}
            className="w-full accent-primary"
            value={settings.chunk_size}
            onChange={e => set({ chunk_size: Number(e.target.value) })}
          />
          <div className="flex justify-between text-xs text-muted-foreground/60 mt-0.5">
            <span>1 (smallest)</span><span>10</span><span>20 (largest)</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── CVE Detail Row ─────────────────────────────────────────────────────────────

function CveCard({ cve, v5 }: { cve: Cve; v5?: CveV5 }) {
  const pocRefs = v5?.pocRefs ?? [];
  return (
    <div className="flex gap-3 items-start rounded-md border border-border/40 bg-background/60 p-3">
      <div className="flex-shrink-0 flex flex-col items-center gap-1 w-20">
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${sevColor(cve.severity)}`}>
          {cve.severity}
        </span>
        <span className="font-mono text-xs text-muted-foreground">{cve.score}</span>
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
            target="_blank" rel="noopener noreferrer"
            className="font-mono text-xs text-primary-400 hover:underline flex items-center gap-1"
            onClick={e => e.stopPropagation()}
          >
            {cve.id} <ExternalLink className="w-3 h-3" />
          </a>
          {cve.is_new && (
            <span className="text-xs bg-red-600 text-white px-1.5 py-0.5 rounded-full">NEW</span>
          )}
          {!cve.verified && (
            <span className="text-xs border border-yellow-500 text-yellow-500 px-1.5 py-0.5 rounded-full flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> unverified
            </span>
          )}
          {v5?.kev && (
            <span
              className="text-xs px-1.5 py-0.5 rounded font-semibold cursor-help"
              style={{ backgroundColor: "rgba(255,97,97,0.15)", color: "#ff6161", border: "1px solid rgba(255,97,97,0.4)" }}
              title="CISA Known Exploited Vulnerabilities (KEV): CISA has confirmed this CVE is being actively exploited in the wild. Sourced from the CISA ADP entry inside the CVE record on github.com/CVEProject/cvelistV5 — not from NVD or Exploit-DB."
            >
              🔥 KEV
            </span>
          )}
          {pocRefs.length > 0 && (
            <span
              className="text-xs px-1.5 py-0.5 rounded font-semibold cursor-help"
              style={{ backgroundColor: "rgba(255,197,51,0.15)", color: "#ffc533", border: "1px solid rgba(255,197,51,0.4)" }}
              title="Proof of Concept (PoC): the CVE record lists reference link(s) tagged exploit / proof-of-concept, or a GitHub link that looks like a PoC repo. Sourced from the CVE record's references on github.com/CVEProject/cvelistV5 — this means a link exists, not that it was verified to work."
            >
              ⚡ PoC
            </span>
          )}
          <span className="text-xs text-muted-foreground ml-auto">{cve.published}</span>
        </div>
        <p className="text-xs text-foreground/70 leading-relaxed">{cve.description}</p>
        {pocRefs.length > 0 && (
          <div className="mt-1.5 space-y-0.5">
            {pocRefs.slice(0, 3).map((ref, i) => (
              <a
                key={i}
                href={ref.url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="flex items-center gap-1 text-[11px] font-mono truncate hover:underline"
                style={{ color: "#ffc533" }}
              >
                <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                <span className="truncate">{ref.url}</span>
              </a>
            ))}
          </div>
        )}
        <CveLookupLinks cveId={cve.id} description={cve.description} />
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function InventoryMonitor() {
  const [inventory, setInventory] = useState<Inventory>({
    last_full_scan: null, technologies: [], projects: [],
  });
  const [status, setStatus]   = useState<Status>({ running: false, last_full_scan: null, progress: null, total_entries: 0 });
  const [loading, setLoading] = useState(true);

  // Filters
  const [sevFilter, setSevFilter]         = useState("ALL");
  const [newOnly, setNewOnly]             = useState(false);
  const [search, setSearch]               = useState("");
  const [projectFilter, setProjectFilter] = useState("all");
  const activeProject = useActiveProject();
  useEffect(() => {
    if (activeProject) setProjectFilter(activeProject);
  }, [activeProject]);

  const [expanded, setExpanded]   = useState<Set<string>>(new Set());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // CVElistV5 enrichment: cve_id → CveV5 data fetched from bridge batch endpoint
  const [cveV5, setCveV5] = useState<Record<string, CveV5>>({});

  // AI
  const [aiSettings, setAiSettings]   = useState<AiSettings>(loadAiSettings);
  const [showAiPanel, setShowAiPanel] = useState(false);
  const [aiRunning, setAiRunning]     = useState(false);
  const [aiProgress, setAiProgress]   = useState<{ done: number; total: number } | null>(null);
  const [aiResults, setAiResults]     = useState<ChunkResult[]>([]);
  const [expandedAi, setExpandedAi]   = useState<Set<number>>(new Set([0]));
  const abortRef = useRef(false);

  // ── Fetch ─────────────────────────────────────────────────────────────────────

  const fetchInventory = useCallback(async (projectToken = "") => {
    try {
      const p = projectToken ? `?projectToken=${encodeURIComponent(projectToken)}` : "";
      const r = await fetch(`${API_BASE}/api/inventory${p}`, { credentials: "include" });
      if (r.ok) {
        const inv: Inventory = await r.json();
        setInventory(inv);
        // Batch-fetch CVElistV5 enrichment for all CVE IDs in the inventory
        const allIds = Array.from(new Set(
          inv.technologies.flatMap(t => t.cves.map(c => c.id))
        )).slice(0, 100);
        if (allIds.length > 0) {
          try {
            const batchResp = await fetch(`${API_BASE}/api/cve/batch`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ ids: allIds }),
            });
            if (batchResp.ok) {
              const batchData: Record<string, CveV5> = await batchResp.json();
              setCveV5(prev => ({ ...prev, ...batchData }));
            }
          } catch {}
        }
      }
    } catch {}
    setLoading(false);
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/inventory/status`, { credentials: "include" });
      if (r.ok) {
        const s: Status = await r.json();
        setStatus(s);
        if (!s.running) {
          if (pollRef.current) clearInterval(pollRef.current);
          pollRef.current = null;
          fetchInventory();
        }
      }
    } catch {}
  }, [fetchInventory]);

  useEffect(() => {
    fetchInventory();
    fetchStatus();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchInventory(projectFilter !== "all" ? projectFilter : "");
    setAiResults([]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectFilter]);

  const startRefresh = async () => {
    try {
      await fetch(`${API_BASE}/api/inventory/refresh`, { method: "POST", credentials: "include" });
      setStatus(s => ({ ...s, running: true }));
      if (!pollRef.current) pollRef.current = setInterval(fetchStatus, 3000);
    } catch {}
  };

  // ── AI Analysis ──────────────────────────────────────────────────────────────

  const runAiAnalysis = async () => {
    const entries = filtered.filter(e => e.cves.length > 0);
    if (!entries.length) return;
    setAiRunning(true);
    abortRef.current = false;
    setAiResults([]);
    setExpandedAi(new Set([0]));
    const chunks = chunkArray(entries, aiSettings.chunk_size);
    setAiProgress({ done: 0, total: chunks.length });

    for (let i = 0; i < chunks.length; i++) {
      if (abortRef.current) break;
      const chunk = chunks[i];
      const userMsg = `## Chunk ${i + 1} of ${chunks.length}\n\n` +
        chunk.map(e => {
          const sorted = sortCvesNewestFirst(e.cves);
          const cveLines = sorted.map(c =>
            `  - ${c.id} [${c.severity} ${c.score}]${c.is_new ? " NEW" : ""}${!c.verified ? " ⚠unverified" : ""}: ${c.description}`
          ).join("\n");
          return `### ${e.product} ${e.version}\nHosts (${e.hostnames.length}): ${e.hostnames.slice(0, 5).join(", ")}${e.hostnames.length > 5 ? " …" : ""}\nPrograms: ${e.programs.join(", ") || "unknown"}\nCVEs (newest first):\n${cveLines || "  (none)"}`;
        }).join("\n\n");

      try {
        const r = await fetch(`${API_BASE}/api/inventory/ai-analyze`, {
          method: "POST", credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            provider: aiSettings.provider, api_key: aiSettings.api_key,
            model: aiSettings.model || undefined, base_url: aiSettings.base_url || undefined,
            system: SYSTEM_PROMPT, messages: [{ role: "user", content: userMsg }], max_tokens: 1500,
          }),
        });
        const data = await r.json();
        setAiResults(prev => [...prev, { index: i, total: chunks.length, text: data.text || "", error: data.error }]);
      } catch (err) {
        setAiResults(prev => [...prev, { index: i, total: chunks.length, text: "", error: String(err) }]);
      }
      setAiProgress({ done: i + 1, total: chunks.length });
    }
    setAiRunning(false);
    setAiProgress(null);
  };

  // ── Filtering ─────────────────────────────────────────────────────────────────

  const toggle = (key: string) =>
    setExpanded(s => { const n = new Set(s); n.has(key) ? n.delete(key) : n.add(key); return n; });

  const filtered = inventory.technologies.filter(t => {
    if (newOnly && !t.cves.some(c => c.is_new)) return false;
    if (sevFilter !== "ALL" && maxSev(t.cves) !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!t.product.includes(q) && !t.version.includes(q) &&
          !t.cves.some(c => c.id.toLowerCase().includes(q))) return false;
    }
    return true;
  });

  const hasNew     = inventory.technologies.some(t => t.cves.some(c => c.is_new));
  const analyzable = filtered.filter(e => e.cves.length > 0).length;

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div className="animate-fade-in">

      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary-400" />
          <h2 className="text-lg font-semibold text-foreground">CVE Inventory Monitor</h2>
          {hasNew && <Badge className="bg-red-600 text-white text-xs animate-pulse">New CVEs</Badge>}
        </div>
        <div className="flex items-center gap-2">
          {status.running
            ? <span className="text-xs font-mono text-muted-foreground">Scanning… {status.progress ?? ""}</span>
            : <span className="text-xs text-muted-foreground">Last scan: {relTime(status.last_full_scan)}</span>
          }
          <Button size="sm" variant="outline" onClick={startRefresh} disabled={status.running}
            className="gap-2 border-border text-foreground/80 hover:text-foreground hover:bg-secondary">
            <RefreshCw className={`w-4 h-4 ${status.running ? "animate-spin" : ""}`} />
            {status.running ? "Scanning…" : "Refresh CVEs"}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setShowAiPanel(v => !v)}
            className={`gap-2 border-border hover:bg-secondary ${showAiPanel ? "text-primary-400 border-primary-400/50" : "text-foreground/80"}`}>
            <BrainCircuit className="w-4 h-4" />
            AI Analysis
          </Button>
        </div>
      </div>

      {showAiPanel && (
        <AiSettingsPanel settings={aiSettings} onChange={setAiSettings} onClose={() => setShowAiPanel(false)} />
      )}

      {/* Filter bar */}
      <div className="flex flex-wrap gap-2 mb-4">
        <select
          className="h-8 px-2 rounded-md border border-border bg-background text-sm text-foreground"
          value={projectFilter}
          onChange={e => setProjectFilter(e.target.value)}
        >
          <option value="all">All projects</option>
          {inventory.projects.map(p => (
            <option key={p.token} value={p.token}>{p.name}</option>
          ))}
        </select>
        <input
          className="h-8 px-3 rounded-md border border-border bg-background text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary-500"
          placeholder="Search product / CVE…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select
          className="h-8 px-2 rounded-md border border-border bg-background text-sm text-foreground"
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}
        >
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => <option key={s}>{s}</option>)}
        </select>
        <label className="flex items-center gap-1.5 h-8 px-3 rounded-md border border-border bg-background text-sm text-foreground cursor-pointer select-none">
          <input type="checkbox" checked={newOnly} onChange={e => setNewOnly(e.target.checked)} />
          New only
        </label>
        {inventory.technologies.length > 0 && (
          <span className="ml-auto text-xs text-muted-foreground self-center">
            {filtered.length} of {inventory.technologies.length} entries
          </span>
        )}
      </div>

      {/* Badge legend — quick-glance meaning of the CVE tags below, with sourcing */}
      {inventory.technologies.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 mb-4 px-3 py-2 rounded-md border border-border/40 bg-secondary/20">
          <span className="text-[11px] font-semibold text-muted-foreground/70 uppercase tracking-wide">Legend</span>
          <span
            className="flex items-center gap-1.5 text-[11px] text-muted-foreground cursor-help"
            title="CISA has confirmed this CVE is being actively exploited in the wild. Sourced from the CISA ADP entry inside the CVE record on github.com/CVEProject/cvelistV5."
          >
            <span className="text-xs px-1.5 py-0.5 rounded font-semibold" style={{ backgroundColor: "rgba(255,97,97,0.15)", color: "#ff6161", border: "1px solid rgba(255,97,97,0.4)" }}>
              🔥 KEV
            </span>
            actively exploited (CISA)
          </span>
          <span
            className="flex items-center gap-1.5 text-[11px] text-muted-foreground cursor-help"
            title="The CVE record links a reference tagged exploit / proof-of-concept, or a GitHub link that looks like a PoC repo. Sourced from the CVE record's references on github.com/CVEProject/cvelistV5 — a link exists, it isn't independently verified to work."
          >
            <span className="text-xs px-1.5 py-0.5 rounded font-semibold" style={{ backgroundColor: "rgba(255,197,51,0.15)", color: "#ffc533", border: "1px solid rgba(255,197,51,0.4)" }}>
              ⚡ PoC
            </span>
            public exploit code linked
          </span>
          <span
            className="flex items-center gap-1.5 text-[11px] text-muted-foreground cursor-help"
            title="This CVE appeared since the last full inventory scan."
          >
            <span className="text-xs bg-red-600 text-white px-1.5 py-0.5 rounded-full">NEW</span>
            new since last scan
          </span>
          <span
            className="flex items-center gap-1.5 text-[11px] text-muted-foreground cursor-help"
            title="The technology → CVE match was made by keyword, not by a confirmed CPE match — double-check version applicability before reporting."
          >
            <span className="text-xs border border-yellow-500 text-yellow-500 px-1.5 py-0.5 rounded-full flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> unverified
            </span>
            keyword match, not CPE-confirmed
          </span>
        </div>
      )}

      {/* Empty state */}
      {!loading && inventory.technologies.length === 0 && (
        <div className="rounded-lg border border-border/50 bg-secondary/30 p-8 text-center tile-hover">
          <ShieldCheck className="w-10 h-10 mx-auto mb-3 text-muted-foreground/40" />
          {inventory.linkedScansCount === 0 ? (
            <>
              <p className="text-muted-foreground text-sm font-medium">No scans linked to this project</p>
              <p className="text-muted-foreground/60 text-xs mt-1">
                Go to the Scans page and link scans to this project to see inventory here.
              </p>
            </>
          ) : (
            <>
              <p className="text-muted-foreground text-sm">No inventory yet.</p>
              <p className="text-muted-foreground/60 text-xs mt-1">
                Click <strong>Refresh CVEs</strong> to scan discovered technologies against NVD.
              </p>
            </>
          )}
        </div>
      )}

      {/* Inventory table */}
      {filtered.length > 0 && (
        <div className="rounded-lg border border-border/50 overflow-hidden mb-6 tile-hover">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50 bg-secondary/50">
                  <th className="w-6 py-2.5 px-3" />
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Product</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Version</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Top CVE</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">CVEs</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">New since scan</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Hosts</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Project</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-muted-foreground uppercase tracking-wide">Checked</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(entry => {
                  const key      = `${entry.product}/${entry.version}`;
                  const open     = expanded.has(key);
                  const top      = topCve(entry.cves);
                  const newCves  = entry.cves.filter(c => c.is_new);
                  const sortedCves = sortCvesNewestFirst(entry.cves);

                  const projectLabels = entry.programs;

                  return (
                    <>
                      <tr key={key}
                        className={`border-b border-border/30 hover:bg-secondary/30 cursor-pointer transition-colors ${open ? "bg-secondary/20" : ""}`}
                        onClick={() => toggle(key)}
                      >
                        <td className="py-2 px-3 text-muted-foreground">
                          {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                        </td>

                        {/* Product */}
                        <td className="py-2 px-3 font-mono text-foreground/90 font-medium">{entry.product}</td>

                        {/* Version */}
                        <td className="py-2 px-3 font-mono text-foreground/70">{entry.version}</td>

                        {/* Top CVE: severity badge + CVE ID + score */}
                        <td className="py-2 px-3">
                          {top ? (
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className={`text-xs font-bold px-1.5 py-0.5 rounded-full ${sevColor(top.severity)}`}>
                                {top.severity}
                              </span>
                              <span className={`font-mono text-xs ${sevDot(top.severity)}`}>{top.id}</span>
                              <span className="text-xs text-muted-foreground">{top.score}</span>
                            </div>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </td>

                        {/* Total CVE count */}
                        <td className="py-2 px-3">
                          <span className="font-mono text-foreground/80">{entry.cve_count}</span>
                        </td>

                        {/* New since last scan */}
                        <td className="py-2 px-3">
                          {newCves.length > 0 ? (
                            <span className="inline-flex items-center gap-1 text-xs bg-red-600/90 text-white px-2 py-0.5 rounded-full font-semibold">
                              +{newCves.length} new
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground/50">—</span>
                          )}
                        </td>

                        {/* Hosts */}
                        <td className="py-2 px-3 text-muted-foreground text-xs">{entry.hostnames.length}</td>

                        {/* Project */}
                        <td className="py-2 px-3 text-muted-foreground text-xs max-w-[180px] truncate"
                            title={projectLabels.join(", ")}>
                          {projectLabels.join(", ") || "—"}
                        </td>

                        {/* Checked */}
                        <td className="py-2 px-3 text-muted-foreground text-xs">{relTime(entry.last_checked)}</td>
                      </tr>

                      {/* Expanded: all CVEs newest-first */}
                      {open && (
                        <tr key={`${key}-detail`} className="bg-secondary/10">
                          <td colSpan={9} className="px-6 py-3">
                            <div className="space-y-2">
                              {/* Affected hosts */}
                              <div className="text-xs text-muted-foreground mb-1">
                                Affected hosts: {entry.hostnames.slice(0, 8).join(", ")}
                                {entry.hostnames.length > 8 && ` +${entry.hostnames.length - 8} more`}
                              </div>

                              {/* CVE list header */}
                              {sortedCves.length > 0 && (
                                <div className="flex items-center gap-2 mb-2">
                                  <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                                    {sortedCves.length} CVE{sortedCves.length !== 1 ? "s" : ""} — newest first
                                  </span>
                                  {newCves.length > 0 && (
                                    <span className="text-xs bg-red-600 text-white px-1.5 py-0.5 rounded-full">
                                      {newCves.length} new since last scan
                                    </span>
                                  )}
                                </div>
                              )}

                              {sortedCves.length === 0 ? (
                                <p className="text-xs text-muted-foreground">No CVEs found in NVD for {entry.product} {entry.version}.</p>
                              ) : (
                                sortedCves.map(cve => <CveCard key={cve.id} cve={cve} v5={cveV5[cve.id]} />)
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Analyze button */}
      {!aiRunning && aiResults.length === 0 && analyzable > 0 && (
        <div className="mb-4 flex items-center gap-3">
          <Button size="sm" variant="outline" onClick={runAiAnalysis}
            className="gap-2 border-border text-foreground/80 hover:text-foreground hover:bg-secondary">
            <BrainCircuit className="w-4 h-4" />
            Analyze {analyzable} entries with AI
          </Button>
          <span className="text-xs text-muted-foreground">
            {Math.ceil(analyzable / aiSettings.chunk_size)} chunk{Math.ceil(analyzable / aiSettings.chunk_size) !== 1 ? "s" : ""} of {aiSettings.chunk_size} — configure provider via <strong>AI Analysis</strong> above
          </span>
        </div>
      )}

      {/* AI Analysis results */}
      {(aiResults.length > 0 || aiRunning) && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <BrainCircuit className="w-4 h-4 text-primary-400" />
              <span className="text-sm font-medium text-foreground">AI Analysis</span>
              {aiRunning && aiProgress && (
                <span className="text-xs text-muted-foreground font-mono">
                  Chunk {aiProgress.done + 1} / {aiProgress.total}…
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {aiRunning && (
                <Button size="sm" variant="outline"
                  onClick={() => { abortRef.current = true; setAiRunning(false); setAiProgress(null); }}
                  className="h-7 text-xs border-border text-destructive hover:bg-destructive/10">
                  Stop
                </Button>
              )}
              {!aiRunning && analyzable > 0 && (
                <Button size="sm" variant="outline" onClick={runAiAnalysis}
                  className="h-7 text-xs gap-1.5 border-border text-foreground/80 hover:bg-secondary">
                  <RefreshCw className="w-3 h-3" /> Re-analyze
                </Button>
              )}
            </div>
          </div>

          {aiRunning && aiProgress && (
            <div className="h-1 rounded-full bg-secondary mb-3 overflow-hidden">
              <div className="h-full bg-primary-500 transition-all duration-300"
                style={{ width: `${(aiProgress.done / aiProgress.total) * 100}%` }} />
            </div>
          )}

          <div className="space-y-2">
            {aiResults.map(result => (
              <div key={result.index} className="rounded-lg border border-border/50 bg-secondary/10 overflow-hidden">
                <button
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-secondary/20 transition-colors"
                  onClick={() => setExpandedAi(s => {
                    const n = new Set(s); n.has(result.index) ? n.delete(result.index) : n.add(result.index); return n;
                  })}
                >
                  {expandedAi.has(result.index)
                    ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />}
                  <span className="text-xs font-medium text-foreground">
                    Chunk {result.index + 1} of {result.total}
                  </span>
                  {result.error && <span className="ml-2 text-xs text-red-400">Error</span>}
                </button>
                {expandedAi.has(result.index) && (
                  <div className="px-4 pb-4 pt-1 border-t border-border/30">
                    {result.error
                      ? <p className="text-xs text-red-400 font-mono">{result.error}</p>
                      : <pre className="text-xs text-foreground/80 leading-relaxed whitespace-pre-wrap font-sans">{result.text}</pre>
                    }
                  </div>
                )}
              </div>
            ))}
            {aiRunning && (
              <div className="rounded-lg border border-border/30 bg-secondary/10 px-4 py-3 flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 text-muted-foreground animate-spin" />
                <span className="text-xs text-muted-foreground">Waiting for AI response…</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
