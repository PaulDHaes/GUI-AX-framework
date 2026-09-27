import React, { useState, useEffect } from "react";
import { Rocket, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

// ─── Types ────────────────────────────────────────────────────────────────────

interface QuickScanPageProps {
  apiUrl: string;
}

interface ScanResult {
  module: string;
  scanId?: string;
  error?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ALL_MODULES = [
  { id: "httpx",        label: "httpx",        description: "HTTP probing & tech detection" },
  { id: "nuclei",       label: "nuclei",       description: "Vulnerability scanning" },
  { id: "subfinder",    label: "subfinder",    description: "Subdomain enumeration" },
  { id: "dnsx",         label: "dnsx",         description: "DNS resolution & brute-force" },
  { id: "gowitness",    label: "gowitness",    description: "Screenshot web targets" },
  { id: "katana",       label: "katana",       description: "Web crawler / spidering" },
  { id: "ffuf",         label: "ffuf",         description: "Directory & parameter fuzzing" },
  { id: "waybackurls",  label: "waybackurls",  description: "Historical URL discovery" },
];

const DEFAULT_MODULES = ["httpx", "nuclei"];

// ─── Component ────────────────────────────────────────────────────────────────

export default function QuickScanPage({ apiUrl }: QuickScanPageProps) {
  // Read URL search params
  const params = new URLSearchParams(
    typeof window !== "undefined" ? window.location.search : ""
  );
  const paramTarget = params.get("target") ?? "";
  const paramModule = params.get("module") ?? "";

  // Form state
  const [target, setTarget] = useState<string>(paramTarget);
  const [selectedModules, setSelectedModules] = useState<string[]>(() => {
    if (paramModule && ALL_MODULES.some((m) => m.id === paramModule)) {
      return [paramModule];
    }
    return DEFAULT_MODULES;
  });
  const [fleetSize, setFleetSize] = useState<number>(3);
  const [scanName, setScanName] = useState<string>(
    paramTarget ? `webapp-${paramTarget}` : ""
  );
  const [extraArgs, setExtraArgs] = useState<string>("");

  // Derived: keep scan name in sync with target unless user has overridden it
  const [scanNameTouched, setScanNameTouched] = useState<boolean>(false);

  useEffect(() => {
    if (!scanNameTouched) {
      setScanName(target ? `webapp-${target}` : "");
    }
  }, [target, scanNameTouched]);

  // Launch state
  const [launching, setLaunching] = useState<boolean>(false);
  const [results, setResults] = useState<ScanResult[]>([]);

  // ── Handlers ────────────────────────────────────────────────────────────────

  const toggleModule = (id: string) => {
    setSelectedModules((prev) =>
      prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
    );
  };

  const handleLaunch = async () => {
    if (!target.trim()) return;
    if (selectedModules.length === 0) return;

    setLaunching(true);
    setResults([]);

    const accumulated: ScanResult[] = [];

    for (const mod of selectedModules) {
      const payload = {
        scanName: scanName.trim() || `webapp-${target.trim()}`,
        module: mod,
        targets: [target.trim()],
        outputFile: "auto",
        fleetControl: {
          spinup: fleetSize,
          rmWhenDone: true,
        },
        ...(extraArgs.trim() ? { options: { extraArgs: extraArgs.trim() } } : {}),
      };

      try {
        const res = await fetch(`${apiUrl}/api/axiom/scan`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (res.ok) {
          const data = await res.json();
          const entry: ScanResult = { module: mod, scanId: data.scanId };
          accumulated.push(entry);
          setResults([...accumulated]);
        } else {
          let errMsg = `HTTP ${res.status}`;
          try {
            const errBody = await res.json();
            errMsg = errBody.error ?? errMsg;
          } catch {
            // ignore parse error
          }
          accumulated.push({ module: mod, error: errMsg });
          setResults([...accumulated]);
        }
      } catch (err) {
        accumulated.push({
          module: mod,
          error: err instanceof Error ? err.message : "Network error",
        });
        setResults([...accumulated]);
      }
    }

    setLaunching(false);
  };

  const isValid = target.trim().length > 0 && selectedModules.length > 0;

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="max-w-2xl mx-auto py-8 px-4 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary-500/10 border border-primary-500/20">
          <Rocket className="h-5 w-5 text-primary-400" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-foreground">Quick Scan</h1>
          <p className="text-sm text-muted-foreground">
            One-click webapp recon — select modules and launch
          </p>
        </div>
      </div>

      {/* Main form card */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-4">
          <CardTitle className="text-base text-foreground">Scan Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">

          {/* Target */}
          <div className="space-y-1.5">
            <Label htmlFor="qs-target" className="text-foreground">
              Target <span className="text-red-400">*</span>
            </Label>
            <Input
              id="qs-target"
              placeholder="example.com or 192.168.1.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-primary-500 font-mono"
            />
            <p className="text-xs text-muted-foreground">Domain or IP address to scan</p>
          </div>

          {/* Modules */}
          <div className="space-y-1.5">
            <Label className="text-foreground">
              Modules <span className="text-red-400">*</span>
            </Label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {ALL_MODULES.map((mod) => {
                const checked = selectedModules.includes(mod.id);
                return (
                  <label
                    key={mod.id}
                    htmlFor={`qs-mod-${mod.id}`}
                    className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                      checked
                        ? "bg-primary-500/10 border-primary-500/40 text-foreground"
                        : "bg-muted/50 border-border text-muted-foreground hover:border-border/70"
                    }`}
                  >
                    <input
                      id={`qs-mod-${mod.id}`}
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleModule(mod.id)}
                      className="mt-0.5 accent-primary-500 h-4 w-4 flex-shrink-0"
                    />
                    <div className="min-w-0">
                      <span className="block text-sm font-medium font-mono">
                        {mod.label}
                      </span>
                      <span className="block text-xs text-muted-foreground mt-0.5">
                        {mod.description}
                      </span>
                    </div>
                  </label>
                );
              })}
            </div>
            {selectedModules.length === 0 && (
              <p className="text-xs text-red-400">Select at least one module</p>
            )}
          </div>

          {/* Fleet Size */}
          <div className="space-y-1.5">
            <Label htmlFor="qs-fleet" className="text-foreground">Fleet Size</Label>
            <Input
              id="qs-fleet"
              type="number"
              min={1}
              max={20}
              value={fleetSize}
              onChange={(e) =>
                setFleetSize(Math.min(20, Math.max(1, parseInt(e.target.value) || 1)))
              }
              className="bg-background border-border text-foreground focus:border-primary-500 w-28"
            />
            <p className="text-xs text-muted-foreground">
              Instances to spin up per module (1–20)
            </p>
          </div>

          {/* Scan Name */}
          <div className="space-y-1.5">
            <Label htmlFor="qs-name" className="text-foreground">Scan Name</Label>
            <Input
              id="qs-name"
              placeholder={target ? `webapp-${target}` : "webapp-example.com"}
              value={scanName}
              onChange={(e) => {
                setScanNameTouched(true);
                setScanName(e.target.value);
              }}
              className="bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-primary-500 font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Auto-filled from target — edit to override
            </p>
          </div>

          {/* Extra Args */}
          <div className="space-y-1.5">
            <Label htmlFor="qs-extra" className="text-foreground">
              Extra Args{" "}
              <span className="text-muted-foreground font-normal">(optional)</span>
            </Label>
            <Input
              id="qs-extra"
              placeholder="-severity critical,high -tags cve"
              value={extraArgs}
              onChange={(e) => setExtraArgs(e.target.value)}
              className="bg-background border-border text-foreground placeholder:text-muted-foreground focus:border-primary-500 font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground">
              Custom flags passed through to the module
            </p>
          </div>

          {/* Launch button */}
          <Button
            onClick={handleLaunch}
            disabled={launching || !isValid}
            className="w-full bg-primary-600 hover:bg-primary-700 text-foreground font-medium py-5"
          >
            {launching ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Launching…
              </>
            ) : (
              <>
                <Rocket className="w-4 h-4 mr-2" />
                Launch Scan
                {selectedModules.length > 1 && (
                  <span className="ml-2 text-xs opacity-70">
                    ({selectedModules.length} modules)
                  </span>
                )}
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Results */}
      {results.length > 0 && (
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-base text-foreground">Launch Results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {results.map((r) => (
              <div
                key={r.module}
                className="flex items-start justify-between gap-3 p-3 rounded-lg bg-muted/30 border border-border"
              >
                <div className="flex items-center gap-2 min-w-0">
                  {r.error ? (
                    <XCircle className="h-4 w-4 text-red-400 flex-shrink-0" />
                  ) : (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0" />
                  )}
                  <span className="text-sm font-mono text-foreground">{r.module}</span>
                </div>
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  {r.error ? (
                    <Badge variant="destructive">{r.error}</Badge>
                  ) : (
                    <Badge variant="success">Queued</Badge>
                  )}
                  {r.scanId && (
                    <span className="text-xs text-muted-foreground font-mono">
                      ID: {r.scanId}
                    </span>
                  )}
                </div>
              </div>
            ))}

            {/* Show in-progress modules */}
            {launching &&
              selectedModules
                .filter((m) => !results.some((r) => r.module === m))
                .map((m) => (
                  <div
                    key={m}
                    className="flex items-center justify-between gap-3 p-3 rounded-lg bg-muted/30 border border-border opacity-60"
                  >
                    <div className="flex items-center gap-2">
                      <Loader2 className="h-4 w-4 text-muted-foreground animate-spin flex-shrink-0" />
                      <span className="text-sm font-mono text-foreground">{m}</span>
                    </div>
                    <Badge variant="outline">Pending…</Badge>
                  </div>
                ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
