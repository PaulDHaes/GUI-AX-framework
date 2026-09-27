import React, { useState, useEffect, useCallback } from "react";
import {
  BookOpen,
  Copy,
  Check,
  Search,
  Filter,
  FileText,
} from "lucide-react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";

const API_BASE = "http://localhost:5000";

// ── Types ────────────────────────────────────────────────────────────────────

interface Wordlist {
  path: string;
  name: string;
  category: string;
  size: number;
  lineCount: number;
  relPath: string;
}

interface WordlistsResponse {
  wordlists: Wordlist[];
  total: number;
}

export interface WordlistManagerProps {
  onSelectWordlist?: (path: string) => void;
}

// ── Categories ────────────────────────────────────────────────────────────────

const ALL_CATEGORIES = [
  "all",
  "subdomains",
  "directories",
  "passwords",
  "usernames",
  "fuzzing",
  "api",
  "general",
] as const;

type Category = (typeof ALL_CATEGORIES)[number];

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatLines(count: number): string {
  return `${count.toLocaleString()} entries`;
}

// ── Skeleton rows ─────────────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <TableRow className="border-border bg-card hover:bg-card">
      {[60, 90, 55, 50, 180, 100].map((w, i) => (
        <TableCell key={i} className="py-3">
          <div
            className="h-3 rounded bg-secondary animate-pulse"
            style={{ width: `${w}px`, maxWidth: "100%" }}
          />
        </TableCell>
      ))}
    </TableRow>
  );
}

// ── Copy button with transient feedback ──────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(
    async (e: React.MouseEvent) => {
      e.stopPropagation();
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      } catch {
        // Clipboard access denied
      }
    },
    [text]
  );

  return (
    <button
      onClick={handleCopy}
      title="Copy path"
      className={`flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${
        copied
          ? "text-success-400 bg-success-500/10"
          : "text-muted-foreground hover:text-foreground hover:bg-secondary"
      }`}
    >
      {copied ? (
        <Check className="w-3.5 h-3.5" />
      ) : (
        <Copy className="w-3.5 h-3.5" />
      )}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// ── Category chip ─────────────────────────────────────────────────────────────

interface ChipProps {
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
}

function CategoryChip({ label, count, active, onClick }: ChipProps) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium transition-colors whitespace-nowrap ${
        active
          ? "bg-primary-500/20 text-primary-400 border border-primary-500/40"
          : "bg-card text-muted-foreground border border-border hover:border-border hover:text-foreground"
      }`}
    >
      {label === "all" ? "All" : label.charAt(0).toUpperCase() + label.slice(1)}
      {count !== undefined && (
        <span
          className={`font-mono ${active ? "text-primary-300" : "text-muted-foreground/80"}`}
        >
          {count}
        </span>
      )}
    </button>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function WordlistManager({ onSelectWordlist }: WordlistManagerProps) {
  const [wordlists, setWordlists] = useState<Wordlist[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [category, setCategory] = useState<Category>("all");
  const [search, setSearch] = useState("");

  // ── Fetch ──────────────────────────────────────────────────────────────────

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`${API_BASE}/api/wordlists`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data: WordlistsResponse) => {
        setWordlists(data.wordlists ?? []);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, []);

  // ── Derived values ─────────────────────────────────────────────────────────

  const categoryCounts: Record<string, number> = { all: wordlists.length };
  for (const wl of wordlists) {
    categoryCounts[wl.category] = (categoryCounts[wl.category] ?? 0) + 1;
  }

  const filtered = wordlists.filter((wl) => {
    if (category !== "all" && wl.category !== category) return false;
    if (
      search.trim() &&
      !wl.name.toLowerCase().includes(search.trim().toLowerCase()) &&
      !wl.relPath.toLowerCase().includes(search.trim().toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3 mb-5">
        <BookOpen className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-semibold text-foreground">Wordlist Catalog</h2>
        {!loading && !error && (
          <span className="text-muted-foreground/80 text-sm font-mono">
            {wordlists.length} total
          </span>
        )}
      </div>

      {/* Search */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/80 pointer-events-none" />
        <Input
          placeholder="Search wordlists…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 bg-card border-border text-foreground placeholder:text-muted-foreground/80 focus:border-primary-500"
        />
        {search && (
          <button
            onClick={() => setSearch("")}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/80 hover:text-foreground/80"
          >
            <Filter className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Category chips */}
      <div className="flex flex-wrap gap-2 mb-5 overflow-x-auto pb-1">
        {ALL_CATEGORIES.map((cat) => {
          const count = categoryCounts[cat];
          // Only show chip if we have entries (or it's "all")
          if (cat !== "all" && !count && !loading) return null;
          return (
            <CategoryChip
              key={cat}
              label={cat}
              count={loading ? undefined : count}
              active={category === cat}
              onClick={() => setCategory(cat)}
            />
          );
        })}
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border overflow-hidden">
        {error ? (
          <div className="p-8 text-center text-danger-400 text-sm">{error}</div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-border bg-background hover:bg-background">
                <TableHead className="text-muted-foreground">Name</TableHead>
                <TableHead className="text-muted-foreground w-[120px]">Category</TableHead>
                <TableHead className="text-muted-foreground w-[130px] text-right">
                  Lines
                </TableHead>
                <TableHead className="text-muted-foreground w-[90px] text-right">
                  Size
                </TableHead>
                <TableHead className="text-muted-foreground">Path</TableHead>
                <TableHead className="text-muted-foreground w-[140px] text-right">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
              ) : filtered.length === 0 ? (
                <TableRow className="border-border hover:bg-transparent">
                  <TableCell colSpan={6} className="py-12 text-center">
                    <FileText className="w-9 h-9 text-muted-foreground/50 mx-auto mb-3" />
                    <p className="text-muted-foreground text-sm">
                      No wordlists found
                      {search ? ` matching "${search}"` : ""}
                    </p>
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((wl, idx) => (
                  <TableRow
                    key={`${wl.path}-${idx}`}
                    className="border-border bg-card hover:bg-secondary/60 transition-colors"
                  >
                    {/* Name */}
                    <TableCell className="py-3">
                      <span className="text-foreground text-sm font-medium">
                        {wl.name}
                      </span>
                    </TableCell>

                    {/* Category */}
                    <TableCell className="py-3">
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-secondary text-muted-foreground border border-border">
                        {wl.category}
                      </span>
                    </TableCell>

                    {/* Lines */}
                    <TableCell className="py-3 text-right">
                      <span className="font-mono text-xs text-foreground/70">
                        {formatLines(wl.lineCount)}
                      </span>
                    </TableCell>

                    {/* Size */}
                    <TableCell className="py-3 text-right">
                      <span className="font-mono text-xs text-muted-foreground">
                        {formatSize(wl.size)}
                      </span>
                    </TableCell>

                    {/* Path */}
                    <TableCell className="py-3 max-w-[240px]">
                      <span
                        className="font-mono text-xs text-muted-foreground truncate block"
                        title={wl.path}
                      >
                        {wl.relPath || wl.path}
                      </span>
                    </TableCell>

                    {/* Actions */}
                    <TableCell className="py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <CopyButton text={wl.path} />
                        {onSelectWordlist && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-2.5 text-xs border-primary-500/40 text-primary-400 hover:bg-primary-500/10 hover:text-primary-300"
                            onClick={() => onSelectWordlist(wl.path)}
                          >
                            Use
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        )}
      </div>

      {/* Footer count */}
      {!loading && !error && filtered.length > 0 && (
        <p className="text-muted-foreground/70 text-xs mt-2 text-right font-mono">
          {filtered.length} of {wordlists.length} wordlist
          {wordlists.length !== 1 ? "s" : ""}
        </p>
      )}
    </div>
  );
}
