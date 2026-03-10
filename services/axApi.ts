// Lightweight ax API client — fixed local base URL for simple deployments.
// If the frontend and ax backend run in the same container/network, localhost:8000
// is a sensible default. Change this constant if you host ax elsewhere.
const BASE = "http://localhost:8000";

async function tryPaths(paths: string[]) {
  for (const p of paths) {
    try {
      const res = await fetch(`${BASE}${p}`, {
        headers: { Accept: "application/json" },
      });
      if (!res.ok) continue;
      const json = await res.json();
      if (json) return json;
    } catch (e) {
      // ignore and try next path
    }
  }
  return null;
}

async function getJSON(path: string) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export async function fetchFleet(): Promise<any[]> {
  const paths = ["/api/fleet", "/fleet", "/api/agents", "/agents"];
  const result = await tryPaths(paths);
  return Array.isArray(result) ? result : [];
}

export async function fetchTargets(): Promise<any[]> {
  const paths = ["/api/targets", "/targets", "/api/hosts", "/hosts"];
  const result = await tryPaths(paths);
  return Array.isArray(result) ? result : [];
}

export async function fetchTargetById(id: string): Promise<any | null> {
  const paths = [
    `/api/targets/${encodeURIComponent(id)}`,
    `/targets/${encodeURIComponent(id)}`,
    `/api/hosts/${encodeURIComponent(id)}`,
    `/hosts/${encodeURIComponent(id)}`,
  ];
  return (await tryPaths(paths)) || null;
}

export async function fetchSubdomainsForTarget(
  idOrDomain: string
): Promise<string[]> {
  const paths = [
    `/api/targets/${encodeURIComponent(idOrDomain)}/subdomains`,
    `/targets/${encodeURIComponent(idOrDomain)}/subdomains`,
    `/api/subdomains?target=${encodeURIComponent(idOrDomain)}`,
    `/subdomains?target=${encodeURIComponent(idOrDomain)}`,
  ];
  const result = await tryPaths(paths);
  return Array.isArray(result) ? result : [];
}

export async function fetchPortsForTarget(idOrDomain: string): Promise<any[]> {
  const paths = [
    `/api/targets/${encodeURIComponent(idOrDomain)}/ports`,
    `/targets/${encodeURIComponent(idOrDomain)}/ports`,
    `/api/ports?target=${encodeURIComponent(idOrDomain)}`,
    `/ports?target=${encodeURIComponent(idOrDomain)}`,
  ];
  const result = await tryPaths(paths);
  return Array.isArray(result) ? result : [];
}

export async function fetchVulnsForTarget(idOrDomain: string): Promise<any[]> {
  const paths = [
    `/api/targets/${encodeURIComponent(idOrDomain)}/vulns`,
    `/targets/${encodeURIComponent(idOrDomain)}/vulns`,
    `/api/vulns?target=${encodeURIComponent(idOrDomain)}`,
    `/vulns?target=${encodeURIComponent(idOrDomain)}`,
  ];
  const result = await tryPaths(paths);
  return Array.isArray(result) ? result : [];
}

export async function listRoot(): Promise<any | null> {
  try {
    const res = await fetch(BASE + "/", {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

export default {
  fetchFleet,
  fetchTargets,
  fetchTargetById,
  fetchSubdomainsForTarget,
  fetchPortsForTarget,
  fetchVulnsForTarget,
  listRoot,
};
