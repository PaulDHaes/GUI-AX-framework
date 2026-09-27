import React, { useEffect, useState, useCallback } from "react";
import { FolderOpen, RefreshCw, ExternalLink, Scan, AlertCircle, Star, Link, Unlink, Plus, ChevronDown } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface AxProject {
  token: string;
  name: string;
  client: string;
  project_type: string;
  ghostwriter_id: number;
  linked_scans?: string[];
}

interface ProjectsPageProps {
  apiUrl: string;
  username: string | null;
}

const ProjectsPage: React.FC<ProjectsPageProps> = ({ apiUrl, username }) => {
  const [projects, setProjects] = useState<AxProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AxProject | null>(null);
  const [activeToken, setActiveToken] = useState<string | null>(null);
  const [settingActive, setSettingActive] = useState(false);

  // Link management state
  const [availablePrograms, setAvailablePrograms] = useState<string[]>([]);
  const [showLinkPanel, setShowLinkPanel] = useState(false);
  const [linkLoading, setLinkLoading] = useState(false);

  const fetchProjects = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`${apiUrl}/api/projects/mine`, { credentials: "include" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      const list: AxProject[] = Array.isArray(data)
        ? data
        : Object.values(data as Record<string, AxProject>);
      setProjects(list);
      if (list.length > 0 && !selected) setSelected(list[0]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [apiUrl]);

  const fetchPrefs = useCallback(async () => {
    try {
      const r = await fetch(`${apiUrl}/api/users/me/prefs`, { credentials: "include" });
      if (r.ok) {
        const prefs = await r.json();
        setActiveToken(prefs.active_project ?? null);
      }
    } catch {}
  }, [apiUrl]);

  const fetchAvailablePrograms = useCallback(async (token: string) => {
    try {
      const r = await fetch(`${apiUrl}/api/projects/${token}/linked-scans`, { credentials: "include" });
      if (r.ok) {
        const data = await r.json();
        setAvailablePrograms(data.available_program_names ?? []);
      }
    } catch {}
  }, [apiUrl]);

  useEffect(() => {
    fetchProjects();
    fetchPrefs();
  }, [fetchProjects, fetchPrefs]);

  useEffect(() => {
    if (selected) {
      fetchAvailablePrograms(selected.token);
      setShowLinkPanel(false);
    }
  }, [selected?.token]);

  const setActiveProject = useCallback(async (token: string) => {
    setSettingActive(true);
    try {
      await fetch(`${apiUrl}/api/users/me/prefs`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ active_project: token }),
      });
      setActiveToken(token);
    } finally {
      setSettingActive(false);
    }
  }, [apiUrl]);

  const linkScan = useCallback(async (programName: string) => {
    if (!selected) return;
    setLinkLoading(true);
    try {
      const r = await fetch(`${apiUrl}/api/axiom/scans/${encodeURIComponent(programName)}/project`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ projectToken: selected.token }),
      });
      if (r.ok) {
        // Update local state optimistically
        setProjects(prev => prev.map(p =>
          p.token === selected.token
            ? { ...p, linked_scans: [...(p.linked_scans ?? []), programName] }
            : p
        ));
        setSelected(prev => prev ? {
          ...prev,
          linked_scans: [...(prev.linked_scans ?? []), programName]
        } : prev);
      }
    } finally {
      setLinkLoading(false);
    }
  }, [apiUrl, selected]);

  const unlinkScan = useCallback(async (programName: string) => {
    if (!selected) return;
    setLinkLoading(true);
    try {
      const r = await fetch(`${apiUrl}/api/axiom/scans/${encodeURIComponent(programName)}/project`, {
        method: "DELETE",
        credentials: "include",
      });
      if (r.ok) {
        setProjects(prev => prev.map(p =>
          p.token === selected.token
            ? { ...p, linked_scans: (p.linked_scans ?? []).filter(s => s !== programName) }
            : p
        ));
        setSelected(prev => prev ? {
          ...prev,
          linked_scans: (prev.linked_scans ?? []).filter(s => s !== programName)
        } : prev);
      }
    } finally {
      setLinkLoading(false);
    }
  }, [apiUrl, selected]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading projects…
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 text-destructive mt-8">
        <AlertCircle className="w-5 h-5" />
        <span>Could not load projects: {error}</span>
        <Button size="sm" variant="outline" onClick={fetchProjects}>Retry</Button>
      </div>
    );
  }

  const linkedScans = selected?.linked_scans ?? [];
  const unlinkedPrograms = availablePrograms.filter(p => !linkedScans.includes(p));

  return (
    <div className="flex gap-4 h-full">
      {/* Project list sidebar */}
      <aside className="w-64 shrink-0 flex flex-col gap-2">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-lg font-semibold flex items-center gap-1">
            <FolderOpen className="w-5 h-5" /> Projects
          </h2>
          <Button size="icon" variant="ghost" onClick={fetchProjects}>
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>

        {projects.length === 0 ? (
          <p className="text-sm text-muted-foreground mt-4">
            No projects assigned yet. Create a project in Ghostwriter and assign yourself to it.
          </p>
        ) : (
          projects.map((p) => (
            <button
              key={p.token}
              onClick={() => setSelected(p)}
              className={`w-full text-left rounded-lg border px-3 py-2 text-sm transition-colors ${
                selected?.token === p.token
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border hover:border-primary/50 hover:bg-muted"
              }`}
            >
              <div className="flex items-center gap-1">
                {activeToken === p.token && (
                  <Star className="w-3 h-3 fill-amber-400 text-amber-400 shrink-0" />
                )}
                <div className="font-medium truncate">{p.client}</div>
              </div>
              <div className="text-xs text-muted-foreground truncate mt-0.5">{p.name}</div>
              <div className="flex items-center gap-2 mt-1">
                {p.project_type && (
                  <Badge variant="outline" className="text-xs">{p.project_type}</Badge>
                )}
                {(p.linked_scans?.length ?? 0) > 0 && (
                  <span className="text-xs text-muted-foreground">
                    <Link className="w-2.5 h-2.5 inline mr-0.5" />
                    {p.linked_scans!.length}
                  </span>
                )}
              </div>
            </button>
          ))
        )}
      </aside>

      {/* Project detail panel */}
      <div className="flex-1 min-w-0">
        {selected ? (
          <div className="flex flex-col gap-4">
            {/* Project header */}
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-xl">{selected.client}</CardTitle>
                    <p className="text-sm text-muted-foreground mt-0.5">{selected.name}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {selected.project_type && (
                      <Badge variant="secondary">{selected.project_type}</Badge>
                    )}
                    {selected.ghostwriter_id > 0 && (
                      <a
                        href={`/rolodex/project/${selected.ghostwriter_id}/`}
                        target="_blank"
                        rel="noopener"
                        className="inline-flex items-center gap-1 text-xs text-blue-500 hover:underline"
                      >
                        <ExternalLink className="w-3 h-3" /> Ghostwriter
                      </a>
                    )}
                    <Button
                      size="sm"
                      variant={activeToken === selected.token ? "default" : "outline"}
                      onClick={() => setActiveProject(selected.token)}
                      disabled={settingActive || activeToken === selected.token}
                      className="flex items-center gap-1"
                      title="Set as active project — filters dashboard and vulns"
                    >
                      <Star className={`w-3.5 h-3.5 ${activeToken === selected.token ? "fill-current" : ""}`} />
                      {activeToken === selected.token ? "Active" : "Set Active"}
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex gap-4 text-sm text-muted-foreground">
                  <span><strong className="text-foreground">{linkedScans.length}</strong> scans linked</span>
                  <span className="font-mono text-xs opacity-60">token: {selected.token.slice(0, 12)}…</span>
                </div>
              </CardContent>
            </Card>

            {/* Linked scans */}
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Scan className="w-4 h-4" /> Linked Scans
                    <span className="text-xs font-normal text-muted-foreground">
                      ({linkedScans.length})
                    </span>
                  </CardTitle>
                  <Button
                    size="sm"
                    variant="outline"
                    className="flex items-center gap-1.5 text-xs"
                    onClick={() => setShowLinkPanel(v => !v)}
                  >
                    <Plus className="w-3 h-3" />
                    Link scan
                    <ChevronDown className={`w-3 h-3 transition-transform ${showLinkPanel ? "rotate-180" : ""}`} />
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {/* Add-scan panel */}
                {showLinkPanel && (
                  <div className="rounded-lg border border-dashed border-border bg-muted/30 p-3">
                    <p className="text-xs text-muted-foreground mb-2 font-medium">
                      Select a scan name to link to this project:
                    </p>
                    {unlinkedPrograms.length === 0 ? (
                      <p className="text-xs text-muted-foreground/60">All available scans are already linked.</p>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {unlinkedPrograms.map(prog => (
                          <button
                            key={prog}
                            disabled={linkLoading}
                            onClick={() => linkScan(prog)}
                            className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-mono bg-secondary hover:bg-primary/20 hover:text-primary border border-border transition-colors disabled:opacity-50"
                          >
                            <Plus className="w-2.5 h-2.5" />
                            {prog}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Currently linked */}
                {linkedScans.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No scans linked yet. Click <strong>Link scan</strong> to associate scan data with this project.
                  </p>
                ) : (
                  <div className="flex flex-col gap-1.5">
                    {linkedScans.map(scanName => (
                      <div
                        key={scanName}
                        className="flex items-center justify-between rounded border border-border px-3 py-2 text-sm bg-card"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <Link className="w-3 h-3 text-primary/70 shrink-0" />
                          <span className="font-mono text-xs truncate">{scanName}</span>
                        </div>
                        <button
                          disabled={linkLoading}
                          onClick={() => unlinkScan(scanName)}
                          title="Unlink this scan from the project"
                          className="ml-2 shrink-0 text-muted-foreground/50 hover:text-destructive transition-colors disabled:opacity-40"
                        >
                          <Unlink className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        ) : (
          <div className="flex items-center justify-center h-64 text-muted-foreground text-sm">
            Select a project from the list
          </div>
        )}
      </div>
    </div>
  );
};

export default ProjectsPage;
