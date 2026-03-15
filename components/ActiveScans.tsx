import React, { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Progress } from "./ui/progress";
import {
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  Play,
  StopCircle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Target,
} from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";

interface Scan {
  id: string;
  name: string;
  module: string;
  // Stats.log format (targets is a number, not array)
  targets?: number | string[];
  instances?: number;
  results?: number;
  runtime?: string;
  // Old format
  outputFile?: string;
  status: "running" | "completed" | "failed" | "cancelled";
  startedAt?: string;
  date?: string; // Stats.log uses "date" instead of "startedAt"
  completedAt?: string;
  progress?: number;
  logs?: string[];
  command?: string;
  threads?: number;
  local_logs?: string;
  remote_logs?: string;
  output?: string;
  failure_reason?: string;
  failure_lines?: string[];
  targetList?: string[];
}

interface ActiveScansProps {
  apiUrl: string;
  onScanSelected?: (scanId: string) => void;
}

export default function ActiveScans({
  apiUrl,
  onScanSelected,
}: ActiveScansProps) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedTargets, setExpandedTargets] = useState<
    Record<string, string[] | null>
  >({});

  const fetchTargetList = async (scanId: string) => {
    if (expandedTargets[scanId] !== undefined) {
      // Toggle off if already open
      setExpandedTargets((prev) => ({
        ...prev,
        [scanId]: prev[scanId] === null ? null : (undefined as any),
      }));
      if (expandedTargets[scanId] !== undefined) {
        setExpandedTargets((prev) => {
          const n = { ...prev };
          delete n[scanId];
          return n;
        });
        return;
      }
    }
    // Mark as loading
    setExpandedTargets((prev) => ({ ...prev, [scanId]: null }));
    try {
      const resp = await fetch(
        `${apiUrl}/api/axiom/scans/${encodeURIComponent(scanId)}/targets`,
      );
      if (resp.ok) {
        const data = await resp.json();
        setExpandedTargets((prev) => ({
          ...prev,
          [scanId]: data.targets ?? [],
        }));
      } else {
        setExpandedTargets((prev) => ({ ...prev, [scanId]: [] }));
      }
    } catch {
      setExpandedTargets((prev) => ({ ...prev, [scanId]: [] }));
    }
  };

  useEffect(() => {
    // Fetch once on mount; subsequent updates via explicit Refresh button
    fetchScans();
    return () => {};
  }, [apiUrl]);

  const fetchScans = async () => {
    console.log(
      "[ActiveScans] Fetching scans from:",
      `${apiUrl}/api/axiom/scans`,
    );
    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/axiom/scans`);
      console.log("[ActiveScans] Stats.log response status:", response.status);

      let statsLogScans: Scan[] = [];
      if (response.ok) {
        statsLogScans = await response.json();
        console.log(
          "[ActiveScans] Stats.log scans count:",
          statsLogScans?.length || 0,
        );
        console.log("[ActiveScans] Stats.log scans detail:");
        statsLogScans?.forEach((s) => {
          console.log(`  - ${s.id}: status=${s.status}, module=${s.module}`);
        });
      } else {
        console.error(
          "[ActiveScans] Stats.log response not OK:",
          response.status,
          response.statusText,
        );
      }

      // Also fetch filesystem scans
      console.log("[ActiveScans] Fetching filesystem discovery...");
      const fsResponse = await fetch(
        `${apiUrl}/api/axiom/scans/filesystem/discover`,
      );
      let filesystemScans: Scan[] = [];
      if (fsResponse.ok) {
        filesystemScans = await fsResponse.json();
        console.log(
          "[ActiveScans] Filesystem scans count:",
          filesystemScans?.length || 0,
        );
        console.log("[ActiveScans] Filesystem scans detail:");
        filesystemScans?.forEach((s) => {
          console.log(
            `  - ${s.id}: status=${s.status}, module=${s.module}, results=${s.results}`,
          );
        });
      } else {
        console.error(
          "[ActiveScans] Filesystem response not OK:",
          fsResponse.status,
        );
      }

      // Merge both sources, preferring filesystem for running scans
      const allScans = [...filesystemScans, ...(statsLogScans || [])];
      console.log(
        "[ActiveScans] Combined scans count (before dedup):",
        allScans.length,
      );

      // Remove duplicates by ID, preferring filesystem version (which appears first in array)
      const uniqueScansMap = new Map(allScans.map((scan) => [scan.id, scan]));
      const uniqueScans = Array.from(uniqueScansMap.values());

      console.log("[ActiveScans] After deduplication:", uniqueScans.length);
      console.log("[ActiveScans] Running vs Completed:");
      const running = uniqueScans.filter((s) => s.status === "running");
      const completed = uniqueScans.filter((s) => s.status === "completed");
      console.log(`  - Running: ${running.length}`);
      running.forEach((s) => console.log(`    * ${s.id}`));
      console.log(`  - Completed: ${completed.length}`);
      completed.forEach((s) => console.log(`    * ${s.id}`));

      setScans(uniqueScans || []);
    } catch (err) {
      console.error("[ActiveScans] Failed to fetch scans:", err);
    } finally {
      setLoading(false);
    }
  };

  const cancelScan = async (scanId: string) => {
    try {
      const response = await fetch(
        `${apiUrl}/api/axiom/scans/${scanId}/cancel`,
        {
          method: "POST",
        },
      );
      if (response.ok) {
        fetchScans();
      }
    } catch (err) {
      console.error("Failed to cancel scan:", err);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "running":
        return <Activity className="h-4 w-4 animate-pulse text-blue-500" />;
      case "completed":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "failed":
        return <XCircle className="h-4 w-4 text-red-500" />;
      case "cancelled":
        return <StopCircle className="h-4 w-4 text-orange-500" />;
      default:
        return <Clock className="h-4 w-4" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, "default" | "secondary" | "destructive"> = {
      running: "default",
      completed: "secondary",
      failed: "destructive",
      cancelled: "secondary",
    };
    return (
      <Badge
        variant={variants[status] || "default"}
        className={
          status === "cancelled"
            ? "bg-orange-900/80 text-orange-100 border border-orange-700"
            : ""
        }
      >
        {status.toUpperCase()}
      </Badge>
    );
  };

  const formatDuration = (startedAt?: string, completedAt?: string) => {
    if (!startedAt) return "N/A";
    const start = new Date(startedAt);
    const end = completedAt ? new Date(completedAt) : new Date();
    const diff = end.getTime() - start.getTime();
    const minutes = Math.floor(diff / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  const getTargetCount = (scan: Scan): number => {
    // Stats.log format has targets as number
    if (typeof scan.targets === "number") {
      return scan.targets;
    }
    // Old format has targets as array
    if (Array.isArray(scan.targets)) {
      return scan.targets.length;
    }
    return 0;
  };

  const getScanStartTime = (scan: Scan): string => {
    // Stats.log uses "date" field, old format uses "startedAt"
    return scan.date || scan.startedAt || new Date().toISOString();
  };

  const runningScans = scans.filter((s) => s.status === "running");
  const completedScans = scans
    .filter((s) => s.status !== "running")
    .sort((a, b) => {
      const aTime = new Date(a.date || a.startedAt || 0).getTime();
      const bTime = new Date(b.date || b.startedAt || 0).getTime();
      return bTime - aTime;
    });

  console.log("[ActiveScans RENDER] runningScans count:", runningScans.length);
  console.log(
    "[ActiveScans RENDER] completedScans count:",
    completedScans.length,
  );
  console.log(
    "[ActiveScans RENDER] Running scans:",
    runningScans.map((s) => ({ id: s.id, status: s.status })),
  );
  console.log(
    "[ActiveScans RENDER] Will show running section?",
    runningScans.length > 0,
  );

  return (
    <div className="space-y-6">
      {/* Debug Panel */}
      {/* <Card className="bg-blue-950 border-blue-900">
        <CardHeader>
          <CardTitle className="text-sm text-blue-300">🔍 Debug Info</CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-blue-200 space-y-1">
          <div>API URL: {apiUrl}</div>
          <div>Total scans loaded: {scans.length}</div>
          <div>Loading: {loading ? "Yes" : "No"}</div>
          <div>Running scans: {runningScans.length}</div>
          <div>Completed scans: {completedScans.length}</div>
          {runningScans.length > 0 && (
            <div className="mt-2 p-2 bg-blue-900/50 rounded">
              <div className="font-semibold mb-1">Latest running scan:</div>
              <pre className="text-[13px] overflow-auto max-h-32">
                {JSON.stringify(runningScans[runningScans.length - 1], null, 2)}
              </pre>
            </div>
          )}
          {runningScans.length === 0 && completedScans.length > 0 && (
            <div className="mt-2 p-2 bg-blue-900/50 rounded">
              <div className="font-semibold mb-1">Latest completed scan:</div>
              <pre className="text-[13px] overflow-auto max-h-32">
                {JSON.stringify(completedScans[0], null, 2)}
              </pre>
            </div>
          )}
        </CardContent>
      </Card> */}

      {/* Running Scans */}
      {runningScans.length > 0 && (
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-white">
                  <Activity className="h-5 w-5 animate-pulse text-emerald-500" />
                  Active Scans ({runningScans.length})
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Currently running distributed scans across your fleet
                </CardDescription>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={fetchScans}
                className="text-xs"
              >
                <RefreshCw className="h-3 w-3 mr-1" />
                Refresh
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {runningScans.map((scan) => (
                <div
                  key={scan.id}
                  className="border border-emerald-900/50 rounded-lg p-4 space-y-3 bg-emerald-950/20 hover:bg-emerald-950/30 transition-colors cursor-pointer"
                  onClick={() => onScanSelected?.(scan.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(scan.status)}
                      <div>
                        <div className="font-semibold text-white">
                          {scan.name}
                        </div>
                        <div className="text-sm text-slate-400">
                          Module:{" "}
                          <span className="text-primary-400">
                            {scan.module}
                          </span>{" "}
                          • {scan.results !== undefined ? scan.results : 0}{" "}
                          results
                          {scan.instances && ` • ${scan.instances} instances`}
                          {scan.targets && ` • ${getTargetCount(scan)} targets`}
                        </div>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        cancelScan(scan.id);
                      }}
                      className="bg-red-900/80 hover:bg-red-800 border border-red-700 text-white-100"
                    >
                      <StopCircle className="h-4 w-4 mr-2" />
                      Cancel
                    </Button>
                  </div>
                  {/* Progress bar + status */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      {(scan.results ?? 0) === 0 ? (
                        <span className="text-amber-400 font-mono flex items-center gap-1.5">
                          <span className="inline-block w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                          Initializing fleet…
                        </span>
                      ) : (
                        <span className="text-emerald-400 font-mono flex items-center gap-1.5">
                          <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                          {scan.results} result{scan.results !== 1 ? "s" : ""}{" "}
                          so far
                        </span>
                      )}
                      <span className="text-slate-500 font-mono">
                        {scan.progress ?? 0}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-700 rounded-full h-1">
                      <div
                        className="bg-emerald-500 h-1 rounded transition-all duration-500"
                        style={{
                          width: `${Math.max(scan.progress ?? 0, (scan.results ?? 0) > 0 ? 5 : 2)}%`,
                        }}
                      />
                    </div>
                  </div>
                  {/* Targets panel */}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      fetchTargetList(scan.id);
                    }}
                    className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors mt-1"
                  >
                    <Target className="w-3 h-3" />
                    {expandedTargets[scan.id] !== undefined
                      ? "Hide targets"
                      : "Show targets"}
                    {expandedTargets[scan.id] !== undefined ? (
                      <ChevronUp className="w-3 h-3" />
                    ) : (
                      <ChevronDown className="w-3 h-3" />
                    )}
                  </button>
                  {expandedTargets[scan.id] !== undefined && (
                    <div className="mt-1 bg-dark-900/60 border border-slate-700 rounded p-2 max-h-40 overflow-y-auto">
                      {expandedTargets[scan.id] === null ? (
                        <p className="text-xs text-slate-500 font-mono">
                          Loading…
                        </p>
                      ) : expandedTargets[scan.id]!.length === 0 ? (
                        <p className="text-xs text-slate-500 font-mono">
                          No target list available
                        </p>
                      ) : (
                        <ul className="space-y-0.5">
                          {expandedTargets[scan.id]!.map((t, i) => (
                            <li
                              key={i}
                              className="text-xs font-mono text-cyan-300"
                            >
                              {t}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scan History */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-white">
                <Clock className="h-5 w-5 text-slate-400" />
                Scan History
              </CardTitle>
              <CardDescription className="text-slate-400">
                Completed, failed, and cancelled scans
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchScans}
              className="bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-700"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {completedScans.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <Clock className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p>No scan history yet</p>
              <p className="text-sm mt-1">Completed scans will appear here</p>
            </div>
          ) : (
            <div className="border border-slate-700 rounded-lg overflow-hidden">
              <Table>
                <TableHeader className="bg-slate-900/50">
                  <TableRow className="border-slate-700 hover:bg-slate-900/50">
                    <TableHead className="text-slate-400">Status</TableHead>
                    <TableHead className="text-slate-400">Scan Name</TableHead>
                    <TableHead className="text-slate-400">Module</TableHead>
                    <TableHead className="text-slate-400">Results</TableHead>
                    <TableHead className="text-slate-400">Targets</TableHead>
                    <TableHead className="text-slate-400">Duration</TableHead>
                    <TableHead className="text-slate-400">Started</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {completedScans.map((scan) => (
                    <React.Fragment key={scan.id}>
                      <TableRow
                        className="border-slate-700 hover:bg-slate-700/30 cursor-pointer transition-colors"
                        onClick={() => onScanSelected?.(scan.id)}
                      >
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getStatusIcon(scan.status)}
                            {getStatusBadge(scan.status)}
                          </div>
                        </TableCell>
                        <TableCell className="font-medium text-white">
                          <div>{scan.name}</div>
                          {scan.status === "failed" && scan.failure_reason && (
                            <div
                              className="text-xs text-red-400 font-mono mt-0.5 max-w-xs truncate"
                              title={[
                                scan.failure_reason,
                                ...(scan.failure_lines ?? []),
                              ].join("\n")}
                            >
                              ⚠ {scan.failure_reason}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold font-mono bg-primary-500/20 border border-primary-500/40 text-white">
                            {scan.module}
                          </span>
                        </TableCell>
                        <TableCell className="text-slate-300">
                          <span
                            className={
                              (scan.results ?? 0) === 0
                                ? "text-red-400 font-mono"
                                : "text-emerald-400 font-mono"
                            }
                          >
                            {scan.results ?? 0}
                          </span>
                        </TableCell>
                        <TableCell className="text-slate-300">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              fetchTargetList(scan.id);
                            }}
                            className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
                            title="Show targets used for this scan"
                          >
                            <Target className="w-3 h-3" />
                            {typeof scan.targets === "number"
                              ? scan.targets
                              : getTargetCount(scan)}
                            {expandedTargets[scan.id] !== undefined ? (
                              <ChevronUp className="w-3 h-3" />
                            ) : (
                              <ChevronDown className="w-3 h-3" />
                            )}
                          </button>
                        </TableCell>
                        <TableCell className="text-slate-300">
                          {scan.runtime ||
                            formatDuration(
                              getScanStartTime(scan),
                              scan.completedAt,
                            )}
                        </TableCell>
                        <TableCell className="text-sm text-slate-400">
                          {new Date(getScanStartTime(scan)).toLocaleString()}
                        </TableCell>
                      </TableRow>
                      {expandedTargets[scan.id] !== undefined && (
                        <TableRow className="border-slate-700 bg-slate-900/40 hover:bg-slate-900/40">
                          <TableCell colSpan={7} className="py-2 px-4">
                            {expandedTargets[scan.id] === null ? (
                              <p className="text-xs text-slate-500 font-mono">
                                Loading targets…
                              </p>
                            ) : expandedTargets[scan.id]!.length === 0 ? (
                              <p className="text-xs text-slate-500 font-mono">
                                No target list available for this scan
                              </p>
                            ) : (
                              <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto py-1">
                                {expandedTargets[scan.id]!.map((t, i) => (
                                  <span
                                    key={i}
                                    className="text-xs font-mono text-cyan-300 bg-dark-800 border border-dark-700 px-2 py-0.5 rounded"
                                  >
                                    {t}
                                  </span>
                                ))}
                              </div>
                            )}
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
