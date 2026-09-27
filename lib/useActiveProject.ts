import { useEffect, useState } from "react";

const API_BASE = "http://localhost:5000";

/** Fetches the user's active project token (`/api/users/me/prefs`), the one
 *  set from the Projects page, so pages with a project filter can default
 *  to it instead of always starting on "all". Returns `null` until loaded
 *  or when no active project is set. */
export function useActiveProject(): string | null {
  const [activeProject, setActiveProject] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(`${API_BASE}/api/users/me/prefs`, { credentials: "include" });
        if (!r.ok) return;
        const prefs = await r.json();
        if (!cancelled && prefs.active_project) setActiveProject(prefs.active_project);
      } catch {
        // no active project preference available; keep default "all"
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return activeProject;
}
