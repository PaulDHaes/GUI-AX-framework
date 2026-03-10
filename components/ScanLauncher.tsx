import React, { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import { Textarea } from "./ui/textarea";
import { Checkbox } from "./ui/checkbox";
import { Rocket, Upload, AlertCircle, X } from "lucide-react";
import { Alert, AlertDescription } from "./ui/alert";

// Go-based tools per provisioner (only available when Go is installed on the image)
const PROVISIONER_GO_TOOLS: Record<string, string[]> = {
  barebones: ["gorgo"],
  default: [
    "amass",
    "anew",
    "assetfinder",
    "chaos-client",
    "crlfuzz",
    "dalfox",
    "dirdar",
    "dnscewl",
    "dnsx",
    "feroxbuster",
    "gau",
    "gauplus",
    "gobuster",
    "gospider",
    "gowitness",
    "gxss",
    "hakrawler",
    "hakrevdns",
    "httprobe",
    "httpx",
    "interactsh-client",
    "jaeles",
    "katana",
    "kiterunner",
    "kxss",
    "massdns",
    "naabu",
    "nuclei",
    "puredns",
    "rustscan",
    "shuffledns",
    "subfinder",
    "subjs",
    "tlsx",
    "unimap",
    "waybackurls",
  ],
  reconftw: [
    "amass",
    "anew",
    "assetfinder",
    "dnsx",
    "gau",
    "gospider",
    "gowitness",
    "gotator",
    "hakrawler",
    "httpx",
    "interactsh-client",
    "katana",
    "nuclei",
    "puredns",
    "subfinder",
    "subjs",
    "unimap",
    "waybackurls",
  ],
  extras: [
    "amass",
    "anew",
    "assetfinder",
    "chaos-client",
    "crlfuzz",
    "dalfox",
    "dnsx",
    "feroxbuster",
    "gau",
    "gauplus",
    "gobuster",
    "gospider",
    "gowitness",
    "gxss",
    "hakrawler",
    "hakrevdns",
    "httprobe",
    "httpx",
    "interactsh-client",
    "jaeles",
    "katana",
    "kiterunner",
    "kxss",
    "massdns",
    "naabu",
    "nuclei",
    "puredns",
    "rustscan",
    "shuffledns",
    "subfinder",
    "subjs",
    "tlsx",
    "unimap",
    "waybackurls",
  ],
};

// Tools available for each Axiom Packer provisioner image (non-Go tools only)
const PROVISIONER_TOOLS: Record<string, string[]> = {
  barebones: [
    "cero",
    "commix",
    "corsy",
    "dnsgen",
    "dnsrecon",
    "exec",
    "ipcdn",
    "linkfinder",
    "masscan",
    "nmap",
    "openredirex",
    "paramspider",
    "trufflehog",
  ],
  default: [
    "aquatone",
    "arjun",
    "cero",
    "commix",
    "dirsearch",
    "dnsvalidator",
    "ffuf",
    "ipcdn",
    "masscan",
    "meg",
    "nmap",
    "s3scanner",
    "scrying",
    "sqlmap",
    "testssl",
    "trufflehog",
    "wafw00f",
    "webscreenshot",
    "whois",
    "wpscan",
  ],
  reconftw: [
    "arjun",
    "brutespray",
    "cf-check",
    "cmseek",
    "corsy",
    "dirsearch",
    "dnsgen",
    "dnsrecon",
    "emailfinder",
    "ffuf",
    "getjswords",
    "gf",
    "gitdorker",
    "github-subdomains",
    "h8mail",
    "jsa",
    "linkfinder",
    "metafinder",
    "nmap",
    "openredirex",
    "oralyzer",
    "ppfuzz",
    "reconftw",
    "s3scanner",
    "testssl",
    "theharvester",
    "udork",
    "webscreenshot",
  ],
  extras: [
    "aquatone",
    "arjun",
    "aws-cli",
    "cero",
    "cloud_enum",
    "commix",
    "dirsearch",
    "dnsvalidator",
    "droopescan",
    "ffuf",
    "ipcdn",
    "linkfinder",
    "masscan",
    "meg",
    "nmap",
    "s3scanner",
    "scrying",
    "secretfinder",
    "sqlmap",
    "testssl",
    "trufflehog",
    "wafw00f",
    "webscreenshot",
    "whois",
    "wpscan",
  ],
};

const PROVISIONER_LABELS: Record<string, string> = {
  barebones: "Barebones",
  default: "Default",
  reconftw: "ReconFTW",
  extras: "Extras",
};

/** Returns true if module is likely available for the given provisioner */
const isModuleAvailable = (
  moduleName: string,
  provisioner: string,
  includeGoTools: boolean,
): boolean => {
  if (!provisioner || provisioner === "unknown") return true;
  const tools = [
    ...(PROVISIONER_TOOLS[provisioner.toLowerCase()] ?? []),
    ...(includeGoTools
      ? (PROVISIONER_GO_TOOLS[provisioner.toLowerCase()] ?? [])
      : []),
  ];
  if (!tools.length) return true;
  const mod = moduleName.toLowerCase();
  return tools.some((tool) => mod.includes(tool) || tool.includes(mod));
};

/** Finds which provisioners include this module (for tooltip text) */
const getRequiredProvisioners = (
  moduleName: string,
  includeGoTools: boolean,
): string[] => {
  return Object.entries(PROVISIONER_TOOLS)
    .filter(([key, tools]) => {
      const mod = moduleName.toLowerCase();
      const allTools = [
        ...tools,
        ...(includeGoTools ? (PROVISIONER_GO_TOOLS[key] ?? []) : []),
      ];
      return allTools.some((t) => mod.includes(t) || t.includes(mod));
    })
    .map(([key]) => PROVISIONER_LABELS[key] ?? key);
};

interface ScanLauncherProps {
  apiUrl: string;
  onScanLaunched?: (scanId: string) => void;
}

export default function ScanLauncher({
  apiUrl,
  onScanLaunched,
}: ScanLauncherProps) {
  const [modules, setModules] = useState<string[]>([]);
  const [scanName, setScanName] = useState("");
  const [targets, setTargets] = useState("");
  const [module, setModule] = useState("");
  const [outputFile, setOutputFile] = useState("");
  const [wordlist, setWordlist] = useState("");
  const [threads, setThreads] = useState("");
  const [maxRuntime, setMaxRuntime] = useState("");
  const [extraArgs, setExtraArgs] = useState("");

  // File options
  const [localWordlist, setLocalWordlist] = useState("");
  const [localFolder, setLocalFolder] = useState("");
  const [localConfig, setLocalConfig] = useState("");

  // Options
  const [dontShuffle, setDontShuffle] = useState(false);
  const [dontSplit, setDontSplit] = useState(false);
  const [expandCidr, setExpandCidr] = useState(false);
  const [anew, setAnew] = useState(false);
  const [quiet, setQuiet] = useState(false);
  const [unsafe, setUnsafe] = useState(false);

  // Provisioner-aware module filtering
  const [detectedProvisioner, setDetectedProvisioner] =
    useState<string>("unknown");
  const [provisioner, setProvisioner] = useState<string>("unknown");
  const [includeGoTools, setIncludeGoTools] = useState(false);
  const [showGoToolsInfo, setShowGoToolsInfo] = useState(false);

  // ax scan fleet control options
  const [spinup, setSpinup] = useState("");
  const [fleetPrefix, setFleetPrefix] = useState("");
  const [regions, setRegions] = useState("");
  const [rmWhenDone, setRmWhenDone] = useState(false);
  const [shutdownWhenDone, setShutdownWhenDone] = useState(false);
  const [customSsh, setCustomSsh] = useState("");
  const [useCache, setUseCache] = useState(false);

  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    fetchModules();
    fetchProvisioner();
  }, []);

  const fetchModules = async () => {
    try {
      const response = await fetch(`${apiUrl}/api/axiom/modules`);
      if (response.ok) {
        const data = await response.json();
        // Remove .json extension from module names
        const cleanModules = (data.modules || []).map((mod: string) =>
          mod.replace(/\.json$/i, ""),
        );
        setModules(cleanModules);
      }
    } catch (err) {
      console.error("Failed to fetch modules:", err);
    }
  };

  const fetchProvisioner = async () => {
    try {
      const response = await fetch(`${apiUrl}/api/axiom/config`);
      if (response.ok) {
        const data = await response.json();
        const p = (data.provisioner || "unknown").toLowerCase();
        setDetectedProvisioner(p);
        setProvisioner(p);
      }
    } catch (err) {
      console.error("Failed to fetch axiom config:", err);
    }
  };

  const handleFileImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const lines = text.split("\n").filter((line) => line.trim());
      setTargets(lines.join("\n"));
      setSuccess(`Imported ${lines.length} targets from ${file.name}`);
    } catch (err) {
      setError(
        `Failed to import file: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    }
  };

  const handleLaunchScan = async () => {
    setError("");
    setSuccess("");

    // Debug logging
    console.log("[ScanLauncher] Form validation check:");
    console.log("  scanName:", scanName, "isEmpty:", !scanName);
    console.log("  targets:", targets, "isEmpty:", !targets);
    console.log("  module:", module, "isEmpty:", !module);

    if (!scanName || !targets || !module) {
      const missing = [];
      if (!scanName) missing.push("scan name");
      if (!targets) missing.push("targets");
      if (!module) missing.push("module");
      const errorMsg = `Please fill in: ${missing.join(", ")}`;
      console.log("[ScanLauncher] Validation failed:", errorMsg);
      setError(errorMsg);
      return;
    }

    setLaunching(true);

    try {
      // Auto-generate output file if not provided
      const finalOutputFile = outputFile || `${scanName}-${module}.txt`;
      console.log(
        "[ScanLauncher] Auto-generated output file:",
        finalOutputFile,
      );

      const payload = {
        scanName,
        targets: targets.split("\n").filter((t) => t.trim()),
        module,
        outputFile: finalOutputFile,
        fleetControl: {
          spinup: spinup ? parseInt(spinup) : undefined,
          fleetPrefix: fleetPrefix || undefined,
          regions: regions
            ? regions.split(",").map((r) => r.trim())
            : undefined,
          rmWhenDone,
          shutdownWhenDone,
          customSsh: customSsh || undefined,
          useCache,
        },
        options: {
          wordlist: wordlist || undefined,
          localWordlist: localWordlist || undefined,
          localFolder: localFolder || undefined,
          localConfig: localConfig || undefined,
          threads: threads ? parseInt(threads) : undefined,
          maxRuntime: maxRuntime || undefined,
          extraArgs: extraArgs || undefined,
          dontShuffle,
          dontSplit,
          expandCidr,
          anew,
          quiet,
          unsafe,
        },
      };

      console.log("[ScanLauncher] Launching scan with payload:", payload);

      const response = await fetch(`${apiUrl}/api/axiom/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      console.log("[ScanLauncher] Response status:", response.status);

      if (response.ok) {
        const result = await response.json();
        console.log("[ScanLauncher] Scan launched successfully:", result);

        // Show different message based on whether instances are being spun up
        if (result.spinup) {
          setSuccess(
            `🚀 Scan launched! Spinning up ${result.spinup} instance(s) - this takes ~3-4 minutes to initialize.` +
              `\n🏷️ Fleet prefix: ${result.fleetPrefix} (instances will be named ${result.fleetPrefix}01, ${result.fleetPrefix}02, ...)` +
              `\n📁 Output: ${result.outputFile}` +
              `\n🖥️ Session: ${result.tmuxSession} (use 'tmux attach -t ${result.tmuxSession}' to monitor)`,
          );
        } else {
          setSuccess(
            `✅ Scan launched! ID: ${result.scanId}` +
              (result.fleetPrefix ? `\n🏷️ Fleet: ${result.fleetPrefix}` : "") +
              `\n📁 Output: ${result.outputFile}` +
              `\n🖥️ Session: ${result.tmuxSession}`,
          );
        }

        setScanName("");
        setTargets("");
        setOutputFile("");
        setWordlist("");
        setThreads("");
        setMaxRuntime("");

        // Notify other parts of the UI (e.g. FleetControlPage) that a scan was launched.
        // This lets the fleet auto-refresh when --rm-when-done instances get deleted.
        window.dispatchEvent(
          new CustomEvent("axiom:scan-launched", {
            detail: {
              scanId: result.scanId,
              fleetPrefix: result.fleetPrefix || fleetPrefix,
              rmWhenDone,
            },
          }),
        );

        if (onScanLaunched) {
          onScanLaunched(result.scanId);
        }
      } else {
        const error = await response.json();
        console.error("[ScanLauncher] Error response:", error);
        setError(error.error || "Failed to launch scan");
      }
    } catch (err) {
      console.error("[ScanLauncher] Exception:", err);
      setError(
        `Error: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    } finally {
      setLaunching(false);
    }
  };

  return (
    <Card className="bg-slate-800 border-slate-700">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-white">
          <Rocket className="h-5 w-5 text-primary-400" />
          Launch Distributed Scan
        </CardTitle>
        <CardDescription className="text-slate-400">
          Create and run large-scale distributed scans across your Axiom fleet.
          Configure targets, select a module, and customize scan parameters.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert
            variant="destructive"
            className="bg-red-950/50 border-red-900 text-white-300"
          >
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {success && (
          <Alert className="bg-emerald-950/50 border-emerald-900 text-emerald-300">
            <AlertDescription className="whitespace-pre-line font-mono text-sm">
              {success}
            </AlertDescription>
          </Alert>
        )}

        {/* Go Tools Info Banner */}
        {showGoToolsInfo && (
          <Alert className="bg-blue-950/50 border-blue-700 text-blue-200 relative pr-10">
            <AlertCircle className="h-4 w-4 text-blue-400" />
            <AlertDescription className="text-sm">
              <span className="font-semibold text-blue-300">
                Go tools enabled. These tools are only available on images built
                with Go support. If your fleet image was not provisioned with
                Go, modules relying on Go binaries will fail at runtime. Make
                sure your packer image includes the Go toolchain.
              </span>
            </AlertDescription>
            <button
              onClick={() => setShowGoToolsInfo(false)}
              className="absolute top-2 right-2 text-blue-400 hover:text-blue-200 transition-colors"
              aria-label="Dismiss"
            >
              <X className="h-4 w-4" />
            </button>
          </Alert>
        )}

        {/* Provisioner / Image Filter */}
        <div className="bg-dark-800/60 border border-dark-700 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[13px] font-semibold text-white">
                Fleet Image Filter
              </p>
              <p className="text-[13px] text-dark-400 mt-0.5">
                Modules not included in the selected image are greyed out in the
                module picker.
              </p>
            </div>
            {detectedProvisioner !== "unknown" && (
              <span className="text-[13px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-md px-2 py-0.5 font-mono">
                auto-detected:{" "}
                {PROVISIONER_LABELS[detectedProvisioner] ?? detectedProvisioner}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {(
              ["unknown", "barebones", "default", "reconftw", "extras"] as const
            ).map((p) => (
              <button
                key={p}
                onClick={() => setProvisioner(p)}
                className={`px-3 py-1 rounded-lg text-[13px] font-medium border transition-colors ${
                  provisioner === p
                    ? "bg-primary-600/20 border-primary-500/50 text-primary-300"
                    : "bg-dark-800 border-dark-700 text-dark-400 hover:text-white hover:border-dark-600"
                }`}
              >
                {p === "unknown" ? "All (no filter)" : PROVISIONER_LABELS[p]}
                {p !== "unknown" && (
                  <span className="ml-1.5 text-[13px] opacity-60">
                    {PROVISIONER_TOOLS[p]?.length ?? 0} tools
                  </span>
                )}
              </button>
            ))}
            {provisioner !== detectedProvisioner &&
              detectedProvisioner !== "unknown" && (
                <button
                  onClick={() => setProvisioner(detectedProvisioner)}
                  className="px-3 py-1 rounded-lg text-[13px] font-medium border border-cyan-700/40 text-cyan-500 hover:text-cyan-300 transition-colors"
                >
                  ↩ Reset to detected
                </button>
              )}
          </div>

          {/* Go Tools Toggle */}
          <div className="flex items-center gap-3 pt-2 border-t border-dark-700/60 mt-2">
            <Checkbox
              id="includeGoTools"
              checked={includeGoTools}
              onCheckedChange={(checked) => {
                setIncludeGoTools(!!checked);
                if (checked) setShowGoToolsInfo(true);
              }}
            />
            <div>
              <label
                htmlFor="includeGoTools"
                className="text-[13px] font-medium cursor-pointer text-slate-300"
              >
                Include Go-based tools
              </label>
              <p className="text-[13px] text-dark-400 mt-0.5">
                Only enable if your fleet image was built with Go support.{" "}
                {provisioner !== "unknown" && (
                  <span className="text-blue-400">
                    +{PROVISIONER_GO_TOOLS[provisioner]?.length ?? 0} additional
                    tools for {PROVISIONER_LABELS[provisioner] ?? provisioner}
                  </span>
                )}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 space-y-6">
          {/* Scan Name */}
          <div>
            <Label htmlFor="scanName" className="text-slate-300">
              Scan Name <span className="text-red-400">*</span>
            </Label>
            <Input
              id="scanName"
              placeholder="e.g., acme-recon"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5"
            />
            <p className="text-xs text-slate-500 mt-1.5">
              Results will be saved as{" "}
              <span className="text-primary-400 font-mono">
                {scanName || "scan-name"}-{module || "module"}.txt
              </span>
            </p>
          </div>

          {/* Targets */}
          <div>
            <Label htmlFor="targets" className="text-slate-300">
              Targets <span className="text-red-400">*</span>
            </Label>
            <div className="flex gap-2 mt-1.5 mb-2">
              <Textarea
                id="targets"
                placeholder="example.com&#10;192.168.1.0/24&#10;api.example.com"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                rows={6}
                className="flex-1 bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 font-mono text-sm"
              />
              <div className="flex flex-col gap-2">
                <label
                  htmlFor="fileImport"
                  className="cursor-pointer bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2 border border-slate-600"
                >
                  <Upload className="w-4 h-4" />
                  Import File
                </label>
                <input
                  id="fileImport"
                  type="file"
                  accept=".txt,.csv,.json"
                  onChange={handleFileImport}
                  className="hidden"
                />
              </div>
            </div>
            <p className="text-xs text-slate-500">
              One target per line (domains, IPs, CIDRs, URLs). Use "Import File"
              to load targets from a text file.
            </p>
          </div>

          {/* Module */}
          <div>
            <Label htmlFor="module" className="text-slate-300">
              Scan Module <span className="text-red-400">*</span>
            </Label>
            {modules.length > 0 ? (
              <>
                <Select value={module} onValueChange={setModule}>
                  <SelectTrigger
                    id="module"
                    className="bg-slate-900 border-slate-700 text-white mt-1.5 hover:bg-slate-800 transition-colors"
                  >
                    <SelectValue placeholder="Select scan module" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700 text-white">
                    {(() => {
                      const available = modules.filter((m) =>
                        isModuleAvailable(m, provisioner, includeGoTools),
                      );
                      const unavailable = modules.filter(
                        (m) =>
                          !isModuleAvailable(m, provisioner, includeGoTools),
                      );
                      return (
                        <>
                          {available.length > 0 && (
                            <SelectGroup>
                              {provisioner !== "unknown" && (
                                <SelectLabel className="text-dark-500 text-[13px] uppercase tracking-wider">
                                  Available —{" "}
                                  {PROVISIONER_LABELS[provisioner] ??
                                    provisioner}{" "}
                                  image{includeGoTools ? " (incl. Go)" : ""}
                                </SelectLabel>
                              )}
                              {available.map((mod) => (
                                <SelectItem key={mod} value={mod}>
                                  {mod}
                                </SelectItem>
                              ))}
                            </SelectGroup>
                          )}
                          {unavailable.length > 0 && (
                            <SelectGroup>
                              <SelectLabel className="text-dark-600 text-[13px] uppercase tracking-wider">
                                Not in{" "}
                                {PROVISIONER_LABELS[provisioner] ?? provisioner}{" "}
                                image
                                {!includeGoTools
                                  ? " (try enabling Go tools)"
                                  : ""}
                              </SelectLabel>
                              {unavailable.map((mod) => {
                                const needed = getRequiredProvisioners(
                                  mod,
                                  includeGoTools,
                                );
                                return (
                                  <SelectItem
                                    key={mod}
                                    value={mod}
                                    disabled
                                    className="opacity-40"
                                  >
                                    {mod}
                                    {needed.length > 0 && (
                                      <span className="ml-2 text-[13px] text-dark-500">
                                        ({needed.join(" / ")})
                                      </span>
                                    )}
                                  </SelectItem>
                                );
                              })}
                            </SelectGroup>
                          )}
                        </>
                      );
                    })()}
                  </SelectContent>
                </Select>
                {provisioner !== "unknown" &&
                  (() => {
                    const unavailCount = modules.filter(
                      (m) => !isModuleAvailable(m, provisioner, includeGoTools),
                    ).length;
                    return unavailCount > 0 ? (
                      <p className="text-[13px] text-dark-500 mt-1.5 flex items-center gap-1">
                        <span className="text-warn-400">{unavailCount}</span>{" "}
                        module{unavailCount !== 1 ? "s" : ""} greyed out — not
                        in{" "}
                        <span className="text-primary-400">
                          {PROVISIONER_LABELS[provisioner] ?? provisioner}
                        </span>{" "}
                        image
                        {!includeGoTools && (
                          <span className="text-blue-400 ml-1">
                            (enable Go tools to unlock more)
                          </span>
                        )}
                      </p>
                    ) : (
                      <p className="text-[13px] text-success-400 mt-1.5">
                        ✓ All modules available for{" "}
                        {PROVISIONER_LABELS[provisioner] ?? provisioner} image
                      </p>
                    );
                  })()}
              </>
            ) : (
              <div className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 mt-1.5 text-slate-500 text-sm">
                No modules found in ~/.axiom/modules
              </div>
            )}
            <p className="text-xs text-slate-500 mt-1.5">
              Choose a scan module from your ~/.axiom/modules directory
            </p>
          </div>

          {/* Output File */}
          <div>
            <Label htmlFor="outputFile" className="text-slate-300">
              Output File <span className="text-red-400">*</span>
            </Label>
            <Input
              id="outputFile"
              placeholder="results.txt"
              value={outputFile}
              onChange={(e) => setOutputFile(e.target.value)}
              className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5"
            />
            <p className="text-xs text-slate-500 mt-1.5">
              Output filename (results will be merged from all instances)
            </p>
          </div>

          <div className="border-t border-slate-700 pt-4">
            <h3 className="text-sm font-semibold text-slate-300 mb-2">
              Fleet Control
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              Specify a fleet prefix to target existing instances, or use "Spin
              up instances" to create new ones. Configure regions, auto-destroy,
              and other fleet options below.
            </p>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="spinup" className="text-slate-300">
                    Spin Up Instances
                  </Label>
                  <Input
                    id="spinup"
                    type="number"
                    min="1"
                    max="100"
                    placeholder="e.g., 50"
                    value={spinup}
                    onChange={(e) => setSpinup(e.target.value)}
                    className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    Provision new instances for the scan (--spinup)
                  </p>
                  {spinup && parseInt(spinup) > 0 && (
                    <p className="text-xs text-amber-400 mt-1 flex items-center gap-1">
                      ⏱️ New instances take ~3-4 minutes to initialize
                    </p>
                  )}
                </div>
                <div>
                  <Label htmlFor="fleetPrefix" className="text-slate-300">
                    Fleet Prefix
                  </Label>
                  <Input
                    id="fleetPrefix"
                    placeholder="e.g., myfleet"
                    value={fleetPrefix}
                    onChange={(e) => setFleetPrefix(e.target.value)}
                    className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    Use specific fleet prefix (--fleet, defaults to
                    selected.conf)
                  </p>
                </div>
              </div>

              <div>
                <Label htmlFor="regions" className="text-slate-300">
                  Round-Robin Regions
                </Label>
                <Input
                  id="regions"
                  placeholder="us-east-1,eu-west-1,ap-southeast-1"
                  value={regions}
                  onChange={(e) => setRegions(e.target.value)}
                  className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1">
                  Comma-separated regions for round-robin distribution
                  (--regions)
                </p>
              </div>

              <div>
                <Label htmlFor="customSsh" className="text-slate-300">
                  Custom SSH Config
                </Label>
                <Input
                  id="customSsh"
                  placeholder="/path/to/custom/ssh/config"
                  value={customSsh}
                  onChange={(e) => setCustomSsh(e.target.value)}
                  className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1">
                  Use custom SSH config file instead of default (--custom-ssh)
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-start space-x-3 p-3 bg-red-950/30 rounded-lg border border-red-900/50">
                  <Checkbox
                    id="rmWhenDone"
                    checked={rmWhenDone}
                    onCheckedChange={(checked) => setRmWhenDone(!!checked)}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <label
                      htmlFor="rmWhenDone"
                      className="text-sm font-medium cursor-pointer text-red-300"
                    >
                      Destroy Each Instance When Done
                    </label>
                    <p className="text-xs text-red-400/70 mt-1">
                      Each instance destroyed after finishing (--rm-when-done)
                    </p>
                  </div>
                </div>

                <div className="flex items-start space-x-3 p-3 bg-yellow-950/30 rounded-lg border border-yellow-900/50">
                  <Checkbox
                    id="shutdownWhenDone"
                    checked={shutdownWhenDone}
                    onCheckedChange={(checked) =>
                      setShutdownWhenDone(!!checked)
                    }
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <label
                      htmlFor="shutdownWhenDone"
                      className="text-sm font-medium cursor-pointer text-yellow-300"
                    >
                      Shutdown Each Instance When Done
                    </label>
                    <p className="text-xs text-yellow-400/70 mt-1">
                      Each instance shutdown after finishing
                      (--shutdown-when-done)
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <Checkbox
                  id="useCache"
                  checked={useCache}
                  onCheckedChange={(checked) => setUseCache(!!checked)}
                />
                <label
                  htmlFor="useCache"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Use Cached SSH Config (--cache)
                </label>
              </div>
            </div>
          </div>

          <div className="border-t border-slate-700 pt-4">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">
              Advanced Options
            </h3>

            <div className="space-y-4">
              {/* Optional: Wordlist */}
              <div>
                <Label htmlFor="wordlist" className="text-slate-300">
                  Remote Wordlist
                </Label>
                <Input
                  id="wordlist"
                  placeholder="/usr/share/wordlists/common.txt"
                  value={wordlist}
                  onChange={(e) => setWordlist(e.target.value)}
                  className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1.5">
                  Path to wordlist already on instances
                </p>
              </div>

              {/* Optional: Local Wordlist Upload */}
              <div>
                <Label htmlFor="localWordlist" className="text-slate-300">
                  Local Wordlist Upload
                </Label>
                <Input
                  id="localWordlist"
                  placeholder="/path/to/local/wordlist.txt"
                  value={localWordlist}
                  onChange={(e) => setLocalWordlist(e.target.value)}
                  className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1.5">
                  Upload and distribute local wordlist across fleet (-wD)
                </p>
              </div>

              {/* Optional: Local Folder */}
              <div>
                <Label htmlFor="localFolder" className="text-slate-300">
                  Local Folder Upload
                </Label>
                <Input
                  id="localFolder"
                  placeholder="/path/to/templates"
                  value={localFolder}
                  onChange={(e) => setLocalFolder(e.target.value)}
                  className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1.5">
                  Upload local folder to all instances (e.g., nuclei templates)
                </p>
              </div>

              {/* Optional: Config File */}
              <div>
                <Label htmlFor="localConfig" className="text-slate-300">
                  Config File
                </Label>
                <Input
                  id="localConfig"
                  placeholder="/path/to/config.yaml"
                  value={localConfig}
                  onChange={(e) => setLocalConfig(e.target.value)}
                  className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
                />
                <p className="text-xs text-slate-500 mt-1.5">
                  Upload config file to all instances
                </p>
              </div>

              {/* Optional: Threads */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="threads" className="text-slate-300">
                    Threads
                  </Label>
                  <Input
                    id="threads"
                    type="number"
                    placeholder="50"
                    value={threads}
                    onChange={(e) => setThreads(e.target.value)}
                    className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5"
                  />
                  <p className="text-xs text-slate-500 mt-1.5">
                    Concurrent threads
                  </p>
                </div>
                <div>
                  <Label htmlFor="maxRuntime" className="text-slate-300">
                    Max Runtime
                  </Label>
                  <Input
                    id="maxRuntime"
                    placeholder="2h or 30m"
                    value={maxRuntime}
                    onChange={(e) => setMaxRuntime(e.target.value)}
                    className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5"
                  />
                  <p className="text-xs text-slate-500 mt-1.5">
                    Kill scan after timeout
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Extra Args */}
          <div>
            <Label htmlFor="extraArgs" className="text-slate-300">
              Extra Arguments
            </Label>
            <Input
              id="extraArgs"
              placeholder="-p- -sV -T4 --open"
              value={extraArgs}
              onChange={(e) => setExtraArgs(e.target.value)}
              className="bg-slate-900 border-slate-700 text-white placeholder:text-slate-500 focus:border-primary-500 mt-1.5 font-mono text-sm"
            />
            <p className="text-xs text-slate-500 mt-1.5">
              Additional arguments passed to the module
            </p>
          </div>

          <div className="border-t border-slate-700 pt-4">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">
              Scan Flags
            </h3>

            {/* Options */}
            <div className="grid grid-cols-2 gap-3">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="dontShuffle"
                  checked={dontShuffle}
                  onCheckedChange={(checked) => setDontShuffle(!!checked)}
                />
                <label
                  htmlFor="dontShuffle"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Don't shuffle targets
                </label>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="dontSplit"
                  checked={dontSplit}
                  onCheckedChange={(checked) => setDontSplit(!!checked)}
                />
                <label
                  htmlFor="dontSplit"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Don't split inputs
                </label>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="expandCidr"
                  checked={expandCidr}
                  onCheckedChange={(checked) => setExpandCidr(!!checked)}
                />
                <label
                  htmlFor="expandCidr"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Expand CIDRs
                </label>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="anew"
                  checked={anew}
                  onCheckedChange={(checked) => setAnew(!!checked)}
                />
                <label
                  htmlFor="anew"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Anew (deduplicate)
                </label>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="quiet"
                  checked={quiet}
                  onCheckedChange={(checked) => setQuiet(!!checked)}
                />
                <label
                  htmlFor="quiet"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Quiet mode
                </label>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="unsafe"
                  checked={unsafe}
                  onCheckedChange={(checked) => setUnsafe(!!checked)}
                />
                <label
                  htmlFor="unsafe"
                  className="text-sm cursor-pointer text-slate-300"
                >
                  Unsafe mode
                </label>
              </div>
            </div>
          </div>

          <Button
            onClick={handleLaunchScan}
            disabled={launching}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white font-medium py-3"
          >
            <Rocket className="w-4 h-4 mr-2" />
            {launching ? "Launching Scan..." : "Launch Scan"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
