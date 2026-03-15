import React, { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import {
  Server,
  Power,
  PowerOff,
  Terminal,
  Trash2,
  Copy,
  AlertCircle,
  EyeOff,
} from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog";
import { Alert, AlertDescription } from "./ui/alert";
import { Textarea } from "./ui/textarea";

interface FleetInstance {
  id: string;
  name: string;
  provider: string;
  ip: string;
  region: string;
  status: string;
  instanceType: string;
  currentTask: string;
  uptime: string;
}

interface FleetControlProps {
  apiUrl: string;
  fleet: FleetInstance[];
  onRefresh?: () => void;
  onNotify?: (type: string, title: string, message: string) => void;
  onHide?: (id: string) => void;
}

export default function FleetControl({
  apiUrl,
  fleet,
  onRefresh,
  onNotify,
  onHide,
}: FleetControlProps) {
  const [selectedInstances, setSelectedInstances] = useState<string[]>([]);
  const [execCommand, setExecCommand] = useState("");
  const [execPattern, setExecPattern] = useState("*");
  const [execOutput, setExecOutput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean;
    title: string;
    message: string;
    action: (() => void) | null;
  }>({
    open: false,
    title: "",
    message: "",
    action: null,
  });

  const handlePowerControl = async (action: "on" | "off", pattern: string) => {
    setLoading(true);
    setError("");
    try {
      const response = await fetch(`${apiUrl}/api/axiom/fleet/power`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, pattern }),
      });

      if (response.ok) {
        onNotify?.(
          "fleet_power",
          `⚡ Power ${action === "off" ? "Off" : "On"}`,
          `Fleet power ${action} applied to ${pattern === "*" ? "all instances" : pattern}`,
        );
        setLoading(false);
      } else {
        const data = await response.json();
        setError(data.error || "Power control failed");
        setLoading(false);
      }
    } catch (err) {
      setError(`Error: ${err instanceof Error ? err.message : "Unknown"}`);
      setLoading(false);
    }
  };

  const showConfirmDialog = (
    title: string,
    message: string,
    action: () => void,
  ) => {
    setConfirmDialog({
      open: true,
      title,
      message,
      action,
    });
  };

  const handleConfirm = () => {
    confirmDialog.action?.();
    setConfirmDialog({ open: false, title: "", message: "", action: null });
  };

  const handleExecCommand = async () => {
    if (!execCommand.trim()) {
      setError("Please enter a command");
      return;
    }

    setLoading(true);
    setError("");
    setExecOutput("");

    try {
      const response = await fetch(`${apiUrl}/api/axiom/fleet/exec`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: execCommand, pattern: execPattern }),
      });

      if (response.ok) {
        const data = await response.json();
        setExecOutput(data.output || data.stderr || "Command executed");
      } else {
        const data = await response.json();
        setError(data.error || "Command execution failed");
      }
    } catch (err) {
      setError(`Error: ${err instanceof Error ? err.message : "Unknown"}`);
    } finally {
      setLoading(false);
    }
  };

  const handleTerminate = async (pattern: string) => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${apiUrl}/api/axiom/fleet/rm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern }),
      });

      if (response.ok) {
        onNotify?.(
          "fleet_terminated",
          `🗑️ Terminated`,
          `${pattern === "*" ? "All instances" : pattern} terminated successfully`,
        );
        setLoading(false);
        // Clear any selection for deleted instances and refresh
        if (pattern === "*") {
          setSelectedInstances([]);
        } else {
          setSelectedInstances((prev) => prev.filter((n) => n !== pattern));
        }
        onRefresh?.();
      } else {
        const data = await response.json();
        setError(data.error || "Terminate failed");
        setLoading(false);
      }
    } catch (err) {
      setError(`Error: ${err instanceof Error ? err.message : "Unknown"}`);
      setLoading(false);
    }
  };

  const copySSHCommand = (instanceName: string) => {
    navigator.clipboard.writeText(`axiom-ssh ${instanceName}`);
  };

  const getStatusBadge = (status: string) => {
    const color =
      status === "active" || status === "running"
        ? "bg-green-500"
        : status === "inactive"
          ? "bg-gray-500"
          : "bg-yellow-500";
    return <Badge className={color}>{status.toUpperCase()}</Badge>;
  };

  return (
    <div className="space-y-4">
      {/* Header with Quick Actions */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Server className="h-5 w-5 text-primary-500" />
            Fleet Management
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Manage your Axiom cloud instances
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onRefresh?.()}
            disabled={loading}
            title="Refresh fleet status"
          >
            <Server className="h-4 w-4 mr-2" />
            Refresh Fleet
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              showConfirmDialog(
                "Power On All Instances",
                "This will power on all axiom-managed instances. This action cannot be undone immediately.",
                () => handlePowerControl("on", "*"),
              )
            }
            disabled={loading}
          >
            <Power className="h-4 w-4 mr-2" />
            Power On All
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              showConfirmDialog(
                "Power Off All Instances",
                "This will power off all axiom-managed instances.",
                () => handlePowerControl("off", "*"),
              )
            }
            disabled={loading}
          >
            <PowerOff className="h-4 w-4 mr-2" />
            Power Off All
          </Button>
          <Dialog>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <Terminal className="h-4 w-4 mr-2" />
                Execute Command
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl bg-slate-800 border-slate-700">
              <DialogHeader>
                <DialogTitle className="text-white">
                  Execute Command on Fleet
                </DialogTitle>
                <DialogDescription className="text-slate-400">
                  Run a shell command across selected instances
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label htmlFor="pattern" className="text-white">
                    Instance Pattern
                  </Label>
                  <Input
                    id="pattern"
                    placeholder="* (all instances) or myfleet*"
                    value={execPattern}
                    onChange={(e) => setExecPattern(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor="command" className="text-white">
                    Command
                  </Label>
                  <Input
                    id="command"
                    placeholder="uptime"
                    value={execCommand}
                    onChange={(e) => setExecCommand(e.target.value)}
                  />
                </div>
                {execOutput && (
                  <div>
                    <Label className="text-white">Output</Label>
                    <Textarea
                      value={execOutput}
                      readOnly
                      rows={10}
                      className="font-mono text-xs"
                    />
                  </div>
                )}
              </div>
              <DialogFooter>
                <Button onClick={handleExecCommand} disabled={loading}>
                  Execute
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          <Button
            variant="destructive"
            size="sm"
            onClick={() =>
              showConfirmDialog(
                "Terminate All Instances",
                "This will permanently terminate all axiom-managed instances. This action CANNOT be undone!",
                () => handleTerminate("*"),
              )
            }
            disabled={loading}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Terminate All
          </Button>
        </div>
      </div>

      {/* Main Fleet Table - Full Width */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Fleet Control ({fleet.length} instances)
          </CardTitle>
          <CardDescription>Manage your Axiom cloud instances</CardDescription>
        </CardHeader>
        <CardContent>
          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {fleet.length === 0 ? (
            <div className="text-center py-8 text-slate-400">
              No instances in fleet. Use "axiom-init" or "axiom-fleet" to launch
              instances.
            </div>
          ) : (
            <>
              {selectedInstances.length > 0 && (
                <div className="mb-3 flex flex-wrap items-center gap-2 px-3 py-2.5 bg-violet-500/10 border border-violet-500/30 rounded-lg">
                  <span className="text-sm text-violet-300 font-mono mr-2">
                    {selectedInstances.length} instance
                    {selectedInstances.length > 1 ? "s" : ""} selected
                  </span>
                  <div className="flex gap-2 ml-auto">
                    {onHide && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          fleet
                            .filter((i) => selectedInstances.includes(i.name))
                            .forEach((i) => onHide(i.id));
                          setSelectedInstances([]);
                        }}
                        className="text-amber-400 border-amber-500/40 hover:bg-amber-500/10"
                        title="Hide selected from list (not deleted)"
                      >
                        <EyeOff className="h-3 w-3 mr-1" />
                        Hide Selected
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        showConfirmDialog(
                          "Power Off Selected",
                          `Power off ${selectedInstances.length} selected instance(s)?`,
                          () =>
                            selectedInstances.forEach((n) =>
                              handlePowerControl("off", n),
                            ),
                        )
                      }
                      disabled={loading}
                    >
                      <PowerOff className="h-3 w-3 mr-1" />
                      Power Off
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() =>
                        showConfirmDialog(
                          "Terminate Selected",
                          `Permanently terminate ${selectedInstances.length} selected instance(s)? This CANNOT be undone!`,
                          () =>
                            selectedInstances.forEach((n) =>
                              handleTerminate(n),
                            ),
                        )
                      }
                      disabled={loading}
                    >
                      <Trash2 className="h-3 w-3 mr-1" />
                      Terminate Selected
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setSelectedInstances([])}
                    >
                      Clear
                    </Button>
                  </div>
                </div>
              )}
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <input
                        type="checkbox"
                        className="h-4 w-4 cursor-pointer accent-violet-500"
                        checked={
                          selectedInstances.length === fleet.length &&
                          fleet.length > 0
                        }
                        onChange={(e) =>
                          setSelectedInstances(
                            e.target.checked ? fleet.map((i) => i.name) : [],
                          )
                        }
                      />
                    </TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Region</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {fleet.map((instance) => (
                    <TableRow
                      key={instance.id}
                      className={
                        selectedInstances.includes(instance.name)
                          ? "bg-violet-500/5"
                          : ""
                      }
                    >
                      <TableCell className="w-10">
                        <input
                          type="checkbox"
                          className="h-4 w-4 cursor-pointer accent-violet-500"
                          checked={selectedInstances.includes(instance.name)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedInstances((prev) => [
                                ...prev,
                                instance.name,
                              ]);
                            } else {
                              setSelectedInstances((prev) =>
                                prev.filter((n) => n !== instance.name),
                              );
                            }
                          }}
                        />
                      </TableCell>
                      <TableCell className="font-medium">
                        {instance.name}
                      </TableCell>
                      <TableCell>{getStatusBadge(instance.status)}</TableCell>
                      <TableCell className="font-mono text-[13px]">
                        {instance.ip}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{instance.provider}</Badge>
                      </TableCell>
                      <TableCell>{instance.region}</TableCell>
                      <TableCell className="text-[13px] text-slate-400">
                        {instance.instanceType}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            //size="sm"
                            onClick={() => copySSHCommand(instance.name)}
                            title="Copy SSH command"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                          <Button
                            variant="ghost"
                            //size="sm"
                            onClick={() =>
                              handlePowerControl("off", instance.name)
                            }
                            title="Power off"
                          >
                            <PowerOff className="h-3 w-3" />
                          </Button>
                          {onHide && (
                            <Button
                              variant="ghost"
                              //size="sm"
                              onClick={() => onHide(instance.id)}
                              title="Hide from list (not deleted)"
                              className="text-slate-500 hover:text-amber-400"
                            >
                              <EyeOff className="h-3 w-3" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            //size="sm"
                            onClick={() =>
                              showConfirmDialog(
                                `Terminate ${instance.name}`,
                                `Permanently terminate "${instance.name}"? This CANNOT be undone.`,
                                () => handleTerminate(instance.name),
                              )
                            }
                            title="Terminate"
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialog */}
      {confirmDialog.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="relative bg-slate-800 border border-slate-700 rounded-lg shadow-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-yellow-500" />
              {confirmDialog.title}
            </h2>
            <p className="text-slate-300 mb-6">{confirmDialog.message}</p>
            <div className="flex justify-end gap-2">
              <Button
                variant="outline"
                onClick={() =>
                  setConfirmDialog({
                    open: false,
                    title: "",
                    message: "",
                    action: null,
                  })
                }
              >
                Cancel
              </Button>
              <Button variant="destructive" onClick={handleConfirm}>
                Confirm
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
