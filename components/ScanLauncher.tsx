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
import {
  PROVISIONER_TOOLS,
  PROVISIONER_LABELS,
  isModuleAvailable,
  getRequiredProvisioners,
} from "../services/provisioner";

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
  const [gowitnesWarn, setGowitnesWarn] = useState<{ bare: string[] } | null>(
    null,
  );
  const [gowitnesRmWarn, setGowitnesRmWarn] = useState(false);

  // Team context
  const [teams, setTeams] = useState<{ id: string; name: string }[]>([]);
  const [selectedTeamId, setSelectedTeamId] = useState<string>("");

  useEffect(() => {
    fetchModules();
    fetchProvisioner();
    fetchTeams();
  }, []);

  const fetchTeams = async () => {
    try {
      const [meRes, teamsRes] = await Promise.all([
        fetch(`${apiUrl}/api/users/me`, { credentials: "include" }),
        fetch(`${apiUrl}/api/teams`, { credentials: "include" }),
      ]);
      if (meRes.ok && teamsRes.ok) {
        const me = await meRes.json();
        const all: { id: string; name: string; createdAt: string }[] =
          await teamsRes.json();
        // Newest joined team first
        const myTeams = all
          .filter((t) => me.teams?.includes(t.id))
          .sort(
            (a, b) =>
              new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
          );
        setTeams(myTeams);
        if (myTeams.length > 0) setSelectedTeamId(myTeams[0].id);
      }
    } catch {
      // backend may not support teams yet
    }
  };

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

  // Core launch logic — no URL checks, called directly after user confirms dialogs
  const doLaunchScan = async () => {
    setLaunching(true);

    try {
      // Prepend team slug prefix when a team is selected
      const teamSlug =
        selectedTeamId && teams.find((t) => t.id === selectedTeamId)
          ? teams
              .find((t) => t.id === selectedTeamId)!
              .name.toLowerCase()
              .replace(/[^a-z0-9]+/g, "-")
              .replace(/^-+|-+$/g, "")
          : "";
      const prefixedScanName = teamSlug ? `${teamSlug}/${scanName}` : scanName;
      const finalOutputFile = outputFile || `${prefixedScanName}-${module}.txt`;
      console.log(
        "[ScanLauncher] Auto-generated output file:",
        finalOutputFile,
      );

      const payload = {
        scanName: prefixedScanName,
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

  const handleLaunchScan = () => {
    setError("");
    setSuccess("");
    if (!scanName || !targets || !module) {
      const missing: string[] = [];
      if (!scanName) missing.push("scan name");
      if (!targets) missing.push("targets");
      if (!module) missing.push("module");
      setError(`Please fill in: ${missing.join(", ")}`);
      return;
    }
    if (module.toLowerCase().includes("gowitness")) {
      const lines = targets
        .split("\n")
        .map((t) => t.trim())
        .filter(Boolean);
      const bare = lines.filter(
        (t) => !t.startsWith("http://") && !t.startsWith("https://"),
      );
      if (bare.length > 0) {
        setGowitnesWarn({ bare });
        return;
      }
    }
    doLaunchScan();
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

        {/* Gowitness URL warning dialog */}
        {gowitnesWarn && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-dark-800 border border-yellow-500/40 rounded-xl shadow-2xl p-6 max-w-md w-full mx-4">
              <div className="flex items-start gap-3 mb-4">
                <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-sm font-bold text-white font-mono mb-1">
                    Gowitness requires full URLs
                  </h3>
                  <p className="text-xs text-white-400">
                    Gowitness needs targets in the form{" "}
                    <code className="text-yellow-300 bg-dark-900 px-1 rounded">
                      https://example.com
                    </code>
                    . The following {gowitnesWarn.bare.length} target
                    {gowitnesWarn.bare.length > 1 ? "s are" : " is"} missing a
                    protocol:
                  </p>
                  <ul className="mt-2 max-h-32 overflow-y-auto space-y-0.5">
                    {gowitnesWarn.bare.map((t) => (
                      <li
                        key={t}
                        className="text-xs font-mono text-yellow-300 bg-dark-900 px-2 py-0.5 rounded"
                      >
                        {t}
                      </li>
                    ))}
                  </ul>
                  <p className="text-xs text-white-500 mt-2">
                    Auto-fix will prefix them with{" "}
                    <code className="text-cyan-300 bg-dark-900 px-1 rounded">
                      https://
                    </code>{" "}
                    (port 443).
                  </p>
                </div>
              </div>
              <div className="flex gap-2 justify-end">
                <button
                  onClick={() => setGowitnesWarn(null)}
                  className="px-3 py-1.5 text-xs rounded border border-dark-600 text-white-400 hover:text-white hover:border-dark-500 transition-colors font-mono"
                >
                  Go back &amp; fix
                </button>
                <button
                  onClick={() => {
                    setGowitnesWarn(null);
                    doLaunchScan();
                  }}
                  className="px-3 py-1.5 text-xs rounded border border-dark-600 text-white-500 hover:text-white transition-colors font-mono"
                >
                  Ignore &amp; launch anyway
                </button>
                <button
                  onClick={() => {
                    const fixed = targets
                      .split("\n")
                      .map((t) => {
                        const trimmed = t.trim();
                        if (!trimmed) return t;
                        if (
                          !trimmed.startsWith("http://") &&
                          !trimmed.startsWith("https://")
                        ) {
                          return `https://${trimmed}`;
                        }
                        return t;
                      })
                      .join("\n");
                    setTargets(fixed);
                    setGowitnesWarn(null);
                  }}
                  className="px-3 py-1.5 text-xs rounded bg-yellow-600 hover:bg-yellow-500 text-white font-mono transition-colors"
                >
                  Auto-fix with https://
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Gowitness rm-when-done warning */}
        {gowitnesRmWarn && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-dark-800 border border-orange-500/40 rounded-xl shadow-2xl p-6 max-w-md w-full mx-4">
              <div className="flex items-start gap-3 mb-4">
                <AlertCircle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-sm font-bold text-white font-mono mb-1">
                    ⚠️ Keep instances alive for gowitness
                  </h3>
                  <p className="text-xs text-white-400 leading-relaxed">
                    <strong className="text-orange-300">
                      rm-when-done has been automatically disabled.
                    </strong>{" "}
                    Gowitness stores screenshots and its SQLite database on the
                    instances. If instances are destroyed before the dashboard
                    downloads them, all screenshots will be lost.
                  </p>
                  <p className="text-xs text-white-500 mt-2">
                    After the scan finishes, use the{" "}
                    <span className="text-cyan-300 font-mono">Fleet</span> tab
                    to SSH in, download the results, then manually remove
                    instances.
                  </p>
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  onClick={() => setGowitnesRmWarn(false)}
                  className="px-4 py-1.5 text-xs rounded bg-orange-700 hover:bg-orange-600 text-white font-mono transition-colors"
                >
                  Got it
                </button>
              </div>
            </div>
          </div>
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
        </div>

        <div className="bg-slate-800 p-6 rounded-lg border border-slate-700 space-y-6">
          {/* Project Team (optional) */}
          <div>
            <Label className="text-slate-300">
              Project Team{" "}
              <span className="text-slate-500 font-normal">(optional)</span>
            </Label>
            <select
              value={selectedTeamId}
              onChange={(e) => setSelectedTeamId(e.target.value)}
              className="mt-1.5 w-full bg-slate-900 border border-slate-700 text-white rounded-md px-3 py-2 text-sm focus:outline-none focus:border-primary-500 font-mono"
            >
              <option value="">— No team / personal scan —</option>
              {teams.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            {selectedTeamId && teams.find((t) => t.id === selectedTeamId) && (
              <p className="text-xs text-slate-500 mt-1.5 font-mono">
                Scan will be prefixed:{" "}
                <span className="text-primary-400">
                  {teams
                    .find((t) => t.id === selectedTeamId)!
                    .name.toLowerCase()
                    .replace(/[^a-z0-9]+/g, "-")
                    .replace(/^-+|-+$/g, "")}
                  /{scanName || "scan-name"}
                </span>
              </p>
            )}
          </div>

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
              {module.toLowerCase().includes("gowitness") ? (
                <>
                  Output:{" "}
                  <span className="text-primary-400 font-mono">
                    {module || "module"}+&lt;timestamp&gt;/
                  </span>{" "}
                  — screenshots + sqlite DB on the instance
                </>
              ) : (
                <>
                  Results will be saved as{" "}
                  <span className="text-primary-400 font-mono">
                    {selectedTeamId &&
                    teams.find((t) => t.id === selectedTeamId)
                      ? `${teams
                          .find((t) => t.id === selectedTeamId)!
                          .name.toLowerCase()
                          .replace(/[^a-z0-9]+/g, "-")
                          .replace(/^-+|-+$/g, "")}/${scanName || "scan-name"}`
                      : scanName || "scan-name"}
                    -{module || "module"}.txt
                  </span>
                </>
              )}
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
                <Select
                  value={module}
                  onValueChange={(val) => {
                    setModule(val);
                    if (val.toLowerCase().includes("gowitness")) {
                      if (rmWhenDone) {
                        setRmWhenDone(false);
                        setGowitnesRmWarn(true);
                      } else {
                        setGowitnesRmWarn(true);
                      }
                    }
                  }}
                >
                  <SelectTrigger
                    id="module"
                    className="bg-slate-900 border-slate-700 text-white mt-1.5 hover:bg-slate-800 transition-colors"
                  >
                    <SelectValue placeholder="Select scan module" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700 text-white">
                    {(() => {
                      const available = modules.filter((m) =>
                        isModuleAvailable(m, provisioner),
                      );
                      const unavailable = modules.filter(
                        (m) => !isModuleAvailable(m, provisioner),
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
                                  image
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
                              </SelectLabel>
                              {unavailable.map((mod) => {
                                const needed = getRequiredProvisioners(mod);
                                return (
                                  <SelectItem
                                    key={mod}
                                    value={mod}
                                    className="opacity-50 italic"
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
                      (m) => !isModuleAvailable(m, provisioner),
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
