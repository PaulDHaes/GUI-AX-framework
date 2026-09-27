import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef,
} from "react";
import {
  AlertTriangle,
  Flag,
  Download,
  Search,
  ChevronDown,
  ChevronRight,
  Shield,
  ExternalLink,
  X,
  Filter,
} from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";
import { ansiToHtml } from "../lib/utils";
import { useActiveProject } from "../lib/useActiveProject";

const API_BASE = "http://localhost:5000";
const PAGE_SIZE = 50;
const SERVER_PAGE_SIZE = 200;

// ── Debounce hook ─────────────────────────────────────────────────────────────
function useDebounce<T>(value: T, delay = 320): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

// ── Types ────────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  path: string;
  matched: string;
  type: string;
  rawContent: string;
  targetId: string;
  targetDomain: string;
  programName?: string;
  affectedDomains?: string[];
  isFalsePositive: boolean;
  isDuplicate: boolean;
}

interface FindingsResponse {
  findings: Finding[];
  total: number;
  linkedScansCount?: number;
}

interface CveRefTagged {
  url: string;
  tags: string[];
  name?: string;
}

interface CveAffected {
  vendor: string;
  product: string;
  versions: string[];
}

interface CveData {
  id: string;
  description: string;
  cvssV3Score: number | null;
  cvssV3Severity: string | null;
  cvssV3Vector: string | null;
  published: string | null;
  references: string[];
  // cvelistV5 enrichment
  pocRefs?: CveRefTagged[];
  kev?: boolean;
  exploitation?: string | null;
  affected?: CveAffected[];
  referencesTagged?: CveRefTagged[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const CVE_REGEX = /CVE-\d{4}-\d+/gi;

function extractCve(text: string): string | null {
  const matches = text.match(CVE_REGEX);
  return matches ? matches[0].toUpperCase() : null;
}

// f.id is the scanner's template/vuln id, which repeats across targets — not a valid React key on its own
function getRowKey(finding: Finding, index: number): string {
  return `${finding.targetId}:${finding.id}:${finding.path}:${index}`;
}

// Nuclei (and most scanners) put the CVE in the finding id/template-id, not always in name/description
function getFindingCveId(finding: Finding): string | null {
  return (
    extractCve(finding.id) ??
    extractCve(finding.name) ??
    extractCve(finding.description) ??
    extractCve(finding.matched ?? "") ??
    extractCve(finding.rawContent ?? "") ??
    null
  );
}

// HackTricks doesn't expose a stable query-string search API, so route through a scoped Google search
function hackTricksSearchUrl(query: string): string {
  return `https://www.google.com/search?q=${encodeURIComponent(`site:hacktricks.wiki ${query}`)}`;
}

function exploitDbSearchUrl(
  cveId: string | null,
  fallbackQuery: string,
): string {
  if (cveId) {
    const cveNumber = cveId.replace(/^CVE-/i, "");
    return `https://www.exploit-db.com/search?cve=${encodeURIComponent(cveNumber)}`;
  }
  return `https://www.exploit-db.com/search?q=${encodeURIComponent(fallbackQuery)}`;
}

// ── Vendor-aware CVE lookup links ──────────────────────────────────────────────

interface VendorAdvisory {
  name: string;
  keywords: string[];
  url: (cve: string) => string;
}

const VENDOR_ADVISORIES: VendorAdvisory[] = [
  { name: "Grafana", keywords: ["grafana"], url: (c) => `https://grafana.com/security/security-advisories/?q=${c}` },
  { name: "Microsoft", keywords: ["microsoft", "windows", "iis", "exchange", "sharepoint", "mshtml", "mssql", "smb", "rdp", "ntlm", "outlook", "defender"], url: (c) => `https://msrc.microsoft.com/update-guide/vulnerability/${c}` },
  { name: "Apache", keywords: ["apache", "httpd", "tomcat", "struts", "log4j", "log4shell", "solr", "kafka", "airflow", "dubbo"], url: () => `https://httpd.apache.org/security/vulnerabilities_24.html` },
  { name: "Nginx", keywords: ["nginx"], url: () => `https://nginx.org/en/security_advisories.html` },
  { name: "OpenSSL", keywords: ["openssl", "heartbleed", "beast", "poodle", "drown", "logjam"], url: () => `https://www.openssl.org/news/vulnerabilities.html` },
  { name: "Cisco", keywords: ["cisco", "ios xe", "asa", "webex", "anyconnect", "meraki", "firepower"], url: (c) => `https://tools.cisco.com/security/center/search.x?publicationTypeIDs=1&q=${c}` },
  { name: "Fortinet", keywords: ["fortinet", "fortios", "fortigate", "fortimanager", "fortiweb", "forticlient", "fortiproxy"], url: (c) => `https://fortiguard.fortinet.com/psirt?name=${c}` },
  { name: "Palo Alto", keywords: ["palo alto", "panos", "pan-os", "globalprotect", "prisma"], url: (c) => `https://security.paloaltonetworks.com/?q=${encodeURIComponent(c)}` },
  { name: "VMware", keywords: ["vmware", "vsphere", "esxi", "vcenter", "nsx", "aria", "horizon"], url: () => `https://www.vmware.com/security/advisories.html` },
  { name: "Citrix", keywords: ["citrix", "netscaler", "xenapp", "xendesktop", "adc"], url: (c) => `https://support.citrix.com/search#/?q=${c}` },
  { name: "F5", keywords: ["f5", "big-ip", "bigip", "icontrol", "tmui"], url: (c) => `https://my.f5.com/manage/s/article/${c}` },
  { name: "Atlassian", keywords: ["atlassian", "jira", "confluence", "bitbucket", "crowd", "bamboo"], url: (c) => `https://jira.atlassian.com/issues/?jql=text+~+"${c}"` },
  { name: "Jenkins", keywords: ["jenkins"], url: () => `https://www.jenkins.io/security/advisories/` },
  { name: "GitLab", keywords: ["gitlab"], url: (c) => `https://gitlab.com/gitlab-org/cves/-/issues?search=${c}` },
  { name: "WordPress", keywords: ["wordpress", "wp-", "wp plugin", "woocommerce"], url: (c) => `https://wpscan.com/vulnerability/search/?text=${c}` },
  { name: "Drupal", keywords: ["drupal"], url: (c) => `https://www.drupal.org/search/site/${c}` },
  { name: "Linux / Red Hat", keywords: ["linux kernel", "kernel", "ubuntu", "debian", "centos", "rhel", "red hat", "fedora", "suse"], url: (c) => `https://access.redhat.com/security/cve/${c}` },
  { name: "Spring", keywords: ["spring", "spring boot", "springboot", "spring framework", "spring security"], url: () => `https://spring.io/security` },
  { name: "Kubernetes", keywords: ["kubernetes", "k8s", "kubectl", "helm", "containerd", "runc", "docker"], url: () => `https://kubernetes.io/docs/reference/issues-security/official-cve-feed/` },
  { name: "Node / npm", keywords: ["node.js", "nodejs", "npm ", " npm", "express", "electron", "webpack"], url: (c) => `https://security.snyk.io/search?q=${c}` },
  { name: "Python / pip", keywords: ["python", "django", "flask", "fastapi", "pillow", "requests", "pypi"], url: (c) => `https://security.snyk.io/search?q=${c}` },
  { name: "Ruby / Rails", keywords: ["ruby", "rails", "rack", "gems"], url: () => `https://rubysec.com/advisories/` },
  { name: "PHP", keywords: ["php", "laravel", "symfony", "zend", "codeigniter"], url: () => `https://www.php.net/security/` },
  { name: "Aruba / HPE", keywords: ["aruba", "airwave", "clearpass", "hpe", "procurve"], url: (c) => `https://www.arubanetworks.com/support-services/security-bulletins/?q=${c}` },
  { name: "SolarWinds", keywords: ["solarwinds", "orion", "npm"], url: () => `https://www.solarwinds.com/trust-center/security-advisories` },
  { name: "Ivanti", keywords: ["ivanti", "pulse secure", "pulse connect", "mobileiron"], url: () => `https://forums.ivanti.com/s/topic/0TO4d000000KXQUGA4/security-advisories` },
  { name: "Juniper", keywords: ["juniper", "junos", "srx", "ex series", "qfx"], url: (c) => `https://kb.juniper.net/InfoCenter/index?page=content&q=${c}` },
];

interface LookupLink { label: string; url: string; }
interface LookupGroup { label: string; links: LookupLink[]; pill: string; }

function buildCveLookups(cveId: string, context: string): LookupGroup[] {
  const cveNum = cveId.replace(/^CVE-/i, "");
  const lower = context.toLowerCase();

  const vendor = VENDOR_ADVISORIES.find((v) =>
    v.keywords.some((kw) => lower.includes(kw))
  );

  const groups: LookupGroup[] = [
    {
      label: "DB",
      pill: "bg-blue-500/10 text-blue-400 border border-blue-500/25 hover:bg-blue-500/20",
      links: [
        { label: "NVD", url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
        { label: "MITRE", url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}` },
        { label: "CISA KEV", url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}` },
      ],
    },
    {
      label: "Exploit",
      pill: "bg-orange-500/10 text-orange-400 border border-orange-500/25 hover:bg-orange-500/20",
      links: [
        { label: "Exploit-DB", url: `https://www.exploit-db.com/search?cve=${cveNum}` },
        { label: "Metasploit", url: `https://www.rapid7.com/db/?q=${cveId}&type=metasploit` },
        { label: "AttackerKB", url: `https://attackerkb.com/search?q=${cveId}` },
        { label: "GitHub PoC", url: `https://github.com/search?q=${cveId}&type=code&s=stars&o=desc` },
      ],
    },
    {
      label: "Research",
      pill: "bg-purple-500/10 text-purple-400 border border-purple-500/25 hover:bg-purple-500/20",
      links: [
        { label: "VulDB", url: `https://vuldb.com/?search.cve=${cveId}` },
        { label: "Snyk", url: `https://security.snyk.io/search?q=${cveId}` },
        { label: "HackTricks", url: hackTricksSearchUrl(cveId) },
      ],
    },
  ];

  if (vendor) {
    groups.splice(2, 0, {
      label: vendor.name,
      pill: "bg-cyan-500/10 text-cyan-400 border border-cyan-500/25 hover:bg-cyan-500/20",
      links: [{ label: vendor.name + " Advisory", url: vendor.url(cveId) }],
    });
  }

  return groups;
}

function CveLookupLinks({ cveId, context }: { cveId: string; context?: string }) {
  const groups = buildCveLookups(cveId, context ?? "");
  return (
    <div className="mt-3 space-y-1.5">
      <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wide font-mono">Research Links</p>
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
              className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono transition-colors ${g.pill}`}
            >
              {l.label}
              <ExternalLink className="w-2.5 h-2.5 flex-shrink-0" />
            </a>
          ))}
        </div>
      ))}
    </div>
  );
}

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const SEVERITY_CLASSES: Record<string, string> = {
  CRITICAL: "bg-danger-500/20 text-danger-400 border border-danger-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border border-orange-500/30",
  MEDIUM: "bg-warn-500/20 text-warn-400 border border-warn-500/30",
  LOW: "bg-success-500/20 text-success-400 border border-success-500/30",
  INFO: "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${
        SEVERITY_CLASSES[severity] ??
        "bg-secondary text-foreground/70 border border-border"
      }`}
    >
      {severity}
    </span>
  );
}

function downloadCSV(findings: Finding[]) {
  const headers = [
    "ID",
    "Name",
    "Severity",
    "Target",
    "Path",
    "Matched",
    "CVE",
    "False Positive",
    "Duplicate",
  ];
  const rows = findings.map((f) => [
    f.id,
    `"${f.name.replace(/"/g, '""')}"`,
    f.severity,
    f.targetDomain,
    `"${(f.path ?? "").replace(/"/g, '""')}"`,
    `"${(f.matched ?? "").replace(/"/g, '""')}"`,
    getFindingCveId(f) ?? "",
    f.isFalsePositive ? "Yes" : "No",
    f.isDuplicate ? "Yes" : "No",
  ]);
  const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `findings-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── CVE Enrichment Panel ──────────────────────────────────────────────────────

function CvePanel({ cveId }: { cveId: string }) {
  const [data, setData] = useState<CveData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/api/cve/${cveId}`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: CveData) => {
        setData(d);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [cveId]);

  if (loading) {
    return (
      <div className="mt-3 rounded-lg bg-background border border-border p-3 text-muted-foreground text-xs animate-pulse">
        Loading CVE data for {cveId}…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="mt-3 rounded-lg bg-background border border-border p-3 text-muted-foreground text-xs">
        Could not load CVE enrichment: {error ?? "No data"}
      </div>
    );
  }

  const scoreColor =
    data.cvssV3Score !== null
      ? data.cvssV3Score >= 9
        ? "text-red-400"
        : data.cvssV3Score >= 7
          ? "text-orange-400"
          : data.cvssV3Score >= 4
            ? "text-yellow-400"
            : "text-green-400"
      : "text-muted-foreground";

  const pocRefs = data.pocRefs ?? [];
  const allTaggedRefs = data.referencesTagged ?? [];
  // For the general references section, show tagged refs if available, else fall back to plain URLs
  const displayRefs = allTaggedRefs.length > 0 ? allTaggedRefs : data.references.map(u => ({ url: u, tags: [], name: "" }));

  return (
    <div className="mt-3 rounded-lg bg-background border border-cyan-500/20 p-4 animate-fade-in space-y-3">
      {/* Header row */}
      <div className="flex items-center flex-wrap gap-2">
        <Shield className="w-4 h-4 text-cyan-400 shrink-0" />
        <span className="text-cyan-400 font-semibold text-sm">{data.id}</span>
        {data.cvssV3Score !== null && (
          <span className={`font-mono font-bold text-base ${scoreColor}`}>
            {data.cvssV3Score.toFixed(1)}
          </span>
        )}
        {data.cvssV3Severity && (
          <SeverityBadge severity={data.cvssV3Severity.toUpperCase()} />
        )}
        {data.kev && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold"
            style={{ backgroundColor: "rgba(255,97,97,0.15)", color: "#ff6161", border: "1px solid rgba(255,97,97,0.4)" }}
            title="CISA Known Exploited Vulnerability — active exploitation confirmed"
          >
            🔥 CISA KEV
          </span>
        )}
        {pocRefs.length > 0 && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold"
            style={{ backgroundColor: "rgba(255,197,51,0.15)", color: "#ffc533", border: "1px solid rgba(255,197,51,0.4)" }}
            title="Public PoC / exploit code available"
          >
            ⚡ PoC available
          </span>
        )}
      </div>

      {data.cvssV3Vector && (
        <p className="font-mono text-xs text-muted-foreground break-all">
          {data.cvssV3Vector}
        </p>
      )}

      <p className="text-foreground/80 text-sm leading-relaxed">
        <span dangerouslySetInnerHTML={{ __html: ansiToHtml(data.description) }} />
      </p>

      {/* PoC / Exploit references — highlighted */}
      {pocRefs.length > 0 && (
        <div className="rounded border p-2 space-y-1" style={{ borderColor: "rgba(255,197,51,0.3)", backgroundColor: "rgba(255,197,51,0.04)" }}>
          <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: "#ffc533" }}>
            PoC / Exploit References ({pocRefs.length})
          </p>
          {pocRefs.map((ref, i) => (
            <a
              key={i}
              href={ref.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs font-mono truncate hover:underline"
              style={{ color: "#ffc533" }}
            >
              <ExternalLink className="w-3 h-3 shrink-0" />
              <span className="truncate">{ref.url}</span>
              {ref.tags.length > 0 && (
                <span className="shrink-0 opacity-60">[{ref.tags.join(", ")}]</span>
              )}
            </a>
          ))}
        </div>
      )}

      {/* Affected products */}
      {(data.affected ?? []).length > 0 && (
        <div>
          <p className="text-muted-foreground text-xs uppercase tracking-wide mb-1">Affected</p>
          <div className="flex flex-wrap gap-1">
            {data.affected!.map((a, i) => (
              <span key={i} className="text-xs px-1.5 py-0.5 rounded border border-border font-mono bg-muted/30">
                {[a.vendor, a.product].filter(Boolean).join(" / ")}
                {a.versions.length > 0 && <span className="opacity-60 ml-1">{a.versions.slice(0, 2).join(", ")}</span>}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* General references */}
      {displayRefs.length > 0 && (
        <div className="space-y-1">
          <p className="text-muted-foreground text-xs uppercase tracking-wide">References</p>
          {displayRefs.slice(0, 5).map((ref, i) => (
            <a
              key={i}
              href={ref.url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 text-xs font-mono truncate group"
            >
              <ExternalLink className="w-3 h-3 shrink-0 group-hover:scale-110 transition-transform" />
              <span className="truncate">{ref.url}</span>
              {ref.tags.length > 0 && (
                <span className="shrink-0 text-muted-foreground opacity-60 text-[10px]">[{ref.tags.join(",")}]</span>
              )}
            </a>
          ))}
        </div>
      )}

      <CveLookupLinks cveId={data.id} context={data.description} />
    </div>
  );
}

// ── SearchSploit Panel (local, offline Exploit-DB search) ────────────────────

interface SearchsploitResult {
  title: string;
  path: string;
  type: string;
  platform: string;
  date: string;
}

function SearchsploitPanel({ query }: { query: string }) {
  const [results, setResults] = useState<SearchsploitResult[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/api/searchsploit/${encodeURIComponent(query)}`)
      .then((r) => r.json())
      .then((d) => {
        if (d.error) setError(d.error);
        else setResults(d.results ?? []);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [query]);

  return (
    <div className="mt-3 rounded-lg bg-background border border-orange-500/20 p-4 animate-fade-in">
      <div className="flex items-center justify-between mb-2">
        <span className="flex items-center gap-2 text-orange-400 font-semibold text-sm">
          <ExternalLink className="w-4 h-4" />
          SearchSploit — "{query}"
        </span>
        <a
          href={exploitDbSearchUrl(/^CVE-/i.test(query) ? query : null, query)}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs font-mono text-muted-foreground hover:text-orange-400 transition-colors"
        >
          exploit-db.com ↗
        </a>
      </div>
      {loading ? (
        <p className="text-muted-foreground text-xs animate-pulse">
          Searching local Exploit-DB…
        </p>
      ) : error ? (
        <p className="text-muted-foreground text-xs">
          {error === "searchsploit is not installed on the bridge host"
            ? "searchsploit isn't installed on this bridge — use the exploit-db.com link instead."
            : `Could not search: ${error}`}
        </p>
      ) : results && results.length > 0 ? (
        <ul className="space-y-1.5">
          {results.map((r, i) => (
            <li key={i} className="text-xs font-mono flex items-center gap-2">
              <span className="text-foreground/80 truncate">{r.title}</span>
              <span className="text-muted-foreground/80 flex-shrink-0">{r.path}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-muted-foreground text-xs">
          No local exploits found for this query.
        </p>
      )}
    </div>
  );
}

// ── AI explain panel ──────────────────────────────────────────────────────────

function AiExplainPanel({ finding }: { finding: Finding }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [text, setText] = useState("");

  const explain = async () => {
    setState("loading");
    const cveId = getFindingCveId(finding);
    const prompt = `You are a penetration testing assistant for a red team. Explain this security finding concisely:

Finding: ${finding.name}
Severity: ${finding.severity}
${cveId ? `CVE: ${cveId}` : ""}
Path/URL: ${finding.path || "N/A"}
${finding.description ? `Description: ${finding.description}` : ""}
${finding.matched ? `Scanner output: ${finding.matched}` : ""}

Provide:
1. What this vulnerability is (1-2 sentences)
2. Why it is dangerous for the target
3. Recommended remediation step

Be concise and technical. Plain text, no markdown.`;

    try {
      const res = await fetch(`${API_BASE}/api/ai/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ prompt, provider: "auto" }),
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
      setText(data.response);
      setState("done");
    } catch (e) {
      setText((e as Error).message);
      setState("error");
    }
  };

  if (state === "idle") {
    return (
      <button
        onClick={explain}
        className="flex items-center gap-1.5 text-xs font-mono text-muted-foreground hover:text-primary-400 transition-colors mt-3"
      >
        <span className="text-primary-400">✦</span> AI explain
      </button>
    );
  }

  if (state === "loading") {
    return (
      <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground font-mono">
        <span className="animate-pulse text-primary-400">✦</span> Asking AI…
      </div>
    );
  }

  return (
    <div className="mt-3 bg-primary-500/5 border border-primary-500/20 rounded-lg p-3">
      <div className="flex items-center gap-1.5 mb-2 text-xs font-mono text-primary-400">
        <span>✦</span>
        <span>AI analysis</span>
        {state === "error" && <span className="text-danger-400 ml-1">(error)</span>}
      </div>
      <p className={`text-xs leading-relaxed whitespace-pre-wrap ${state === "error" ? "text-danger-400" : "text-foreground/80"}`}>
        {text}
      </p>
      <button
        onClick={() => setState("idle")}
        className="mt-2 text-xs text-muted-foreground hover:text-foreground/70 font-mono transition-colors"
      >
        dismiss
      </button>
    </div>
  );
}

// ── Expanded Row ──────────────────────────────────────────────────────────────

function ExpandedFinding({ finding }: { finding: Finding }) {
  const cveId = getFindingCveId(finding);
  const exploitQuery = cveId ?? finding.name;

  return (
    <div className="px-4 py-4 bg-background/60 border-t border-border">
      {finding.description && (
        <p className="text-foreground/80 text-sm leading-relaxed mb-2">
          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(finding.description) }} />
        </p>
      )}
      {finding.rawContent && finding.rawContent !== finding.description && (
        <pre className="font-mono text-xs text-muted-foreground bg-background rounded p-3 overflow-x-auto max-h-40 mb-2 whitespace-pre-wrap">
          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(finding.rawContent) }} />
        </pre>
      )}
      {cveId && <CvePanel cveId={cveId} />}
      <SearchsploitPanel query={exploitQuery} />
      {/* Show full lookup links for CVE findings; for non-CVE, show just the exploit+research tiers */}
      {cveId
        ? null /* CvePanel already includes CveLookupLinks */
        : (
          <div className="mt-3 space-y-1.5">
            <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wide font-mono">Research Links</p>
            <div className="flex flex-wrap gap-1.5 items-center">
              <span className="text-[10px] text-muted-foreground/40 font-mono w-16 flex-shrink-0">Search</span>
              <a href={hackTricksSearchUrl(exploitQuery)} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border bg-purple-500/10 text-purple-400 border-purple-500/25 hover:bg-purple-500/20 transition-colors">
                HackTricks <ExternalLink className="w-2.5 h-2.5" />
              </a>
              <a href={`https://www.exploit-db.com/search?q=${encodeURIComponent(exploitQuery)}`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border bg-orange-500/10 text-orange-400 border-orange-500/25 hover:bg-orange-500/20 transition-colors">
                Exploit-DB <ExternalLink className="w-2.5 h-2.5" />
              </a>
              <a href={`https://github.com/search?q=${encodeURIComponent(exploitQuery)}&type=code&s=stars&o=desc`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono border bg-orange-500/10 text-orange-400 border-orange-500/25 hover:bg-orange-500/20 transition-colors">
                GitHub PoC <ExternalLink className="w-2.5 h-2.5" />
              </a>
            </div>
          </div>
        )
      }
      <AiExplainPanel finding={finding} />
    </div>
  );
}

// ── Stats Bar ─────────────────────────────────────────────────────────────────

interface StatsBarProps {
  findings: Finding[];
  total?: number | null;
}

function StatsBar({ findings, total }: StatsBarProps) {
  const counts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
    FP: 0,
  };
  for (const f of findings) {
    if (f.isFalsePositive) {
      counts.FP++;
    } else {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
  }

  const stats = [
    { label: "Total", value: total ?? findings.length, cls: "text-foreground" },
    { label: "Critical", value: counts.CRITICAL, cls: "text-danger-400" },
    { label: "High", value: counts.HIGH, cls: "text-orange-400" },
    { label: "Medium", value: counts.MEDIUM, cls: "text-warn-400" },
    { label: "Low", value: counts.LOW, cls: "text-success-400" },
    { label: "False Pos.", value: counts.FP, cls: "text-muted-foreground" },
  ];

  return (
    <div className="flex flex-wrap gap-3 mb-5">
      {stats.map((s) => (
        <div
          key={s.label}
          className="bg-card border border-border rounded-lg px-4 py-2 flex flex-col items-center min-w-[70px]"
        >
          <span className={`font-mono text-xl font-bold ${s.cls}`}>
            {s.value}
          </span>
          <span className="text-muted-foreground text-xs mt-0.5">{s.label}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

interface AxProject {
  token: string;
  name: string;
  client: string;
}

export default function FindingsTriage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters — search is debounced so typing doesn't re-fetch on every keystroke
  const [severity, setSeverity] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [targetFilter, setTargetFilter] = useState<string>("all");
  const [projectFilter, setProjectFilter] = useState<string>("all");
  const activeProject = useActiveProject();
  useEffect(() => {
    if (activeProject) setProjectFilter(activeProject);
  }, [activeProject]);
  const [showFP, setShowFP] = useState(false);
  const [uniqueOnly, setUniqueOnly] = useState(false);
  const debouncedSearch = useDebounce(search, 320);

  // Projects for filter dropdown
  const [projects, setProjects] = useState<AxProject[]>([]);
  useEffect(() => {
    fetch(`${API_BASE}/api/projects/mine`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : [])
      .then((d) => setProjects(Array.isArray(d) ? d : Object.values(d)))
      .catch(() => {});
  }, []);

  // Pagination — page is client-side within the server batch
  const [page, setPage] = useState(0);
  const [serverTotal, setServerTotal] = useState<number | null>(null);
  const [linkedScansCount, setLinkedScansCount] = useState<number | null>(null);

  // UI state
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [fpLoading, setFpLoading] = useState<string | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  // ── Fetch — only fires when debounced search changes ───────────────────────

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (severity !== "all") params.set("severity", severity);
      if (debouncedSearch.trim()) params.set("q", debouncedSearch.trim());
      if (showFP) params.set("fp", "true");
      if (targetFilter !== "all") params.set("target", targetFilter);

      // Pass projectToken so the bridge filters by scans linked to this project,
      // not by client prefix (which would match all scans across a client).
      if (projectFilter !== "all") {
        params.set("projectToken", projectFilter);
      }

      params.set("limit", String(SERVER_PAGE_SIZE));
      const res = await fetch(`${API_BASE}/api/findings?${params.toString()}`, { credentials: "include" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: FindingsResponse = await res.json();
      setFindings(data.findings ?? []);
      setServerTotal(data.total ?? null);
      setLinkedScansCount(data.linkedScansCount ?? null);
      setPage(0); // reset to first page on new results
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [severity, debouncedSearch, showFP, targetFilter, projectFilter]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  // Reset page when filters change
  useEffect(() => {
    setPage(0);
  }, [severity, targetFilter, showFP, uniqueOnly]);

  // ── Derived values (memoised) ──────────────────────────────────────────────

  const allTargets = useMemo(
    () =>
      Array.from(
        new Map(findings.map((f) => [f.targetId, f.targetDomain])).entries(),
      ).sort((a, b) => a[1].localeCompare(b[1])),
    [findings],
  );

  const sortedFindings = useMemo(() => {
    let list = findings;

    // No client-side project prefix filter — bridge now filters by linked scans via projectToken.

    if (uniqueOnly) {
      const seen = new Set<string>();
      list = list.filter((f) => {
        if (f.isDuplicate) return false;
        const k = `${f.name}__${f.severity}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    }
    return [...list].sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99),
    );
  }, [findings, uniqueOnly]);

  const totalPages = Math.ceil(sortedFindings.length / PAGE_SIZE);
  const pagedFindings = useMemo(
    () => sortedFindings.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [sortedFindings, page],
  );

  const gotoPage = (p: number) => {
    setPage(p);
    tableRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  // ── FP toggle ──────────────────────────────────────────────────────────────

  const handleToggleFP = async (f: Finding, rowKey: string) => {
    setFpLoading(rowKey);
    try {
      const res = await fetch(`${API_BASE}/api/findings/mark-fp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetId: f.targetId,
          vulnId: f.id,
          isFalsePositive: !f.isFalsePositive,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await fetchFindings();
    } catch {
      // Silently fail — user can retry
    } finally {
      setFpLoading(null);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-warn-400" />
          <h2 className="text-lg font-semibold text-foreground">Findings Triage</h2>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="border-border text-foreground/80 hover:text-foreground hover:bg-secondary gap-2"
          onClick={() => downloadCSV(sortedFindings)}
          disabled={sortedFindings.length === 0}
        >
          <Download className="w-4 h-4" />
          Export CSV
        </Button>
      </div>

      {/* Stats bar */}
      <StatsBar findings={findings} total={serverTotal} />

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/80 pointer-events-none" />
          <Input
            placeholder="Search findings…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 bg-card border-border text-foreground placeholder:text-muted-foreground/80 focus:border-primary-500"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/80 hover:text-foreground/80"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-[150px] bg-card border-border text-foreground">
            <Filter className="w-3.5 h-3.5 mr-1.5 text-muted-foreground" />
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border text-foreground">
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="CRITICAL">Critical</SelectItem>
            <SelectItem value="HIGH">High</SelectItem>
            <SelectItem value="MEDIUM">Medium</SelectItem>
            <SelectItem value="LOW">Low</SelectItem>
            <SelectItem value="INFO">Info</SelectItem>
          </SelectContent>
        </Select>

        <Select value={targetFilter} onValueChange={(v) => { setTargetFilter(v); }}>
          <SelectTrigger className="w-[180px] bg-card border-border text-foreground">
            <SelectValue placeholder="All targets" />
          </SelectTrigger>
          <SelectContent className="bg-card border-border text-foreground">
            <SelectItem value="all">All targets</SelectItem>
            {allTargets.map(([id, domain]) => (
              <SelectItem key={id} value={id}>
                {domain}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {projects.length > 0 && (
          <Select value={projectFilter} onValueChange={(v) => { setProjectFilter(v); }}>
            <SelectTrigger className="w-[180px] bg-card border-border text-foreground">
              <SelectValue placeholder="All projects" />
            </SelectTrigger>
            <SelectContent className="bg-card border-border text-foreground">
              <SelectItem value="all">All projects</SelectItem>
              {projects.map((p) => (
                <SelectItem key={p.token} value={p.token}>
                  {p.client} — {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {/* Toggles — onClick lives on the label so clicking the text also toggles, not just the tiny knob */}
        <label
          onClick={() => setShowFP((v) => !v)}
          className="flex items-center gap-2 cursor-pointer select-none"
        >
          <div
            className={`w-8 h-4 rounded-full transition-colors ${
              showFP ? "bg-primary-500" : "bg-secondary"
            } relative flex-shrink-0`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
                showFP ? "translate-x-4" : ""
              }`}
            />
          </div>
          <span className="text-foreground/70 text-sm">Show FPs</span>
        </label>

        <label
          onClick={() => setUniqueOnly((v) => !v)}
          className="flex items-center gap-2 cursor-pointer select-none"
        >
          <div
            className={`w-8 h-4 rounded-full transition-colors ${
              uniqueOnly ? "bg-cyan-500" : "bg-secondary"
            } relative flex-shrink-0`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
                uniqueOnly ? "translate-x-4" : ""
              }`}
            />
          </div>
          <span className="text-foreground/70 text-sm">Unique only</span>
        </label>
      </div>

      {/* Main table */}
      <div
        ref={tableRef}
        className="rounded-xl border border-border overflow-hidden"
      >
        {loading ? (
          <div className="p-8 flex items-center justify-center gap-3 text-muted-foreground">
            <svg
              className="w-5 h-5 animate-spin text-primary-400"
              viewBox="0 0 24 24"
              fill="none"
            >
              <circle
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="3"
                strokeDasharray="31.4 62.8"
              />
            </svg>
            Loading findings…
          </div>
        ) : error ? (
          <div className="p-8 text-center text-danger-400 text-sm">{error}</div>
        ) : sortedFindings.length === 0 ? (
          <div className="p-10 text-center">
            <Shield className="w-10 h-10 text-muted-foreground/60 mx-auto mb-3" />
            {linkedScansCount === 0 ? (
              <>
                <p className="text-muted-foreground text-sm font-medium">No scans linked to this project</p>
                <p className="text-muted-foreground/60 text-xs mt-1">
                  Go to the Scans page and link scans to this project to see findings here.
                </p>
              </>
            ) : (
              <p className="text-muted-foreground text-sm">
                No findings match your filters
              </p>
            )}
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-border bg-background hover:bg-background">
                <TableHead className="text-muted-foreground w-6" />
                <TableHead className="text-muted-foreground w-[110px]">
                  Severity
                </TableHead>
                <TableHead className="text-muted-foreground">Finding</TableHead>
                <TableHead className="text-muted-foreground">Target</TableHead>
                <TableHead className="text-muted-foreground w-[130px]">CVE</TableHead>
                <TableHead className="text-muted-foreground max-w-[200px]">
                  Path / Matched
                </TableHead>
                <TableHead className="text-muted-foreground w-10 text-right">
                  FP
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pagedFindings.map((f, idx) => {
                const rowKey = getRowKey(f, idx);
                const isExpanded = expandedId === rowKey;
                const cveId = getFindingCveId(f);
                return (
                  <React.Fragment key={rowKey}>
                    <TableRow
                      className={`border-border cursor-pointer triage-row ${
                        f.isFalsePositive
                          ? "opacity-40 bg-card"
                          : "bg-card"
                      } ${isExpanded ? "bg-secondary/40" : ""}`}
                      onClick={() =>
                        setExpandedId((id) => (id === rowKey ? null : rowKey))
                      }
                    >
                      <TableCell className="py-2.5 pl-3 pr-0 text-muted-foreground/80">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="py-2.5">
                        <span className="text-foreground text-sm font-medium">
                          <span dangerouslySetInnerHTML={{ __html: ansiToHtml(f.name) }} />
                        </span>
                        {f.isDuplicate && (
                          <Badge
                            variant="outline"
                            className="ml-2 text-muted-foreground/80 border-border text-xs py-0"
                          >
                            dup
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {f.affectedDomains && f.affectedDomains.length > 1 ? (
                          <span
                            className="font-mono text-xs text-muted-foreground/80 cursor-default"
                            title={f.affectedDomains.join(", ")}
                          >
                            multiple ({f.affectedDomains.length})
                          </span>
                        ) : (
                          <span className="font-mono text-xs text-foreground/70">
                            {f.targetDomain}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {cveId ? (
                          <span className="font-mono text-xs text-cyan-400">
                            {cveId}
                          </span>
                        ) : (
                          <span className="text-muted-foreground/60 text-xs">—</span>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5 max-w-[200px]">
                        <span
                          className="font-mono text-xs text-muted-foreground truncate block"
                          title={f.path || f.matched}
                        >
                          {(f.path || f.matched)
                            ? <span dangerouslySetInnerHTML={{ __html: ansiToHtml(f.path || f.matched) }} />
                            : "—"}
                        </span>
                      </TableCell>
                      <TableCell
                        className="py-2.5 text-right pr-3"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          disabled={fpLoading === rowKey}
                          onClick={() => handleToggleFP(f, rowKey)}
                          title={
                            f.isFalsePositive
                              ? "Unmark false positive"
                              : "Mark as false positive"
                          }
                          className={`p-1.5 rounded transition-colors ${
                            f.isFalsePositive
                              ? "text-warn-400 hover:text-warn-300 bg-warn-500/10 hover:bg-warn-500/20"
                              : "text-muted-foreground/70 hover:text-warn-400 hover:bg-warn-500/10"
                          } ${fpLoading === rowKey ? "opacity-40 cursor-wait" : ""}`}
                        >
                          <Flag className="w-3.5 h-3.5" />
                        </button>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="border-border hover:bg-transparent">
                        <TableCell colSpan={7} className="p-0">
                          <ExpandedFinding finding={f} />
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}
      </div>

      {!loading && !error && sortedFindings.length > 0 && (
        <div className="flex items-center justify-between mt-3 px-1">
          <p className="text-muted-foreground/80 text-xs font-mono">
            {sortedFindings.length} finding
            {sortedFindings.length !== 1 ? "s" : ""}
            {serverTotal !== null && serverTotal > SERVER_PAGE_SIZE
              ? ` (showing first ${SERVER_PAGE_SIZE} of ${serverTotal})`
              : ""}
            {uniqueOnly && findings.length !== sortedFindings.length
              ? ` | ${findings.length - sortedFindings.length} duplicates hidden`
              : ""}
            {totalPages > 1 && ` | page ${page + 1}/${totalPages}`}
          </p>
          {totalPages > 1 && (
            <div className="flex items-center gap-1.5">
              <button
                className="page-btn"
                onClick={() => gotoPage(0)}
                disabled={page === 0}
              >
                &lt;&lt;
              </button>
              <button
                className="page-btn"
                onClick={() => gotoPage(page - 1)}
                disabled={page === 0}
              >
                &lt;
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                const p =
                  totalPages <= 7
                    ? i
                    : Math.max(0, Math.min(totalPages - 7, page - 3)) + i;
                return (
                  <button
                    key={p}
                    className={`page-btn ${p === page ? "page-btn-active" : ""}`}
                    onClick={() => gotoPage(p)}
                  >
                    {p + 1}
                  </button>
                );
              })}
              <button
                className="page-btn"
                onClick={() => gotoPage(page + 1)}
                disabled={page >= totalPages - 1}
              >
                &gt;
              </button>
              <button
                className="page-btn"
                onClick={() => gotoPage(totalPages - 1)}
                disabled={page >= totalPages - 1}
              >
                &gt;&gt;
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
