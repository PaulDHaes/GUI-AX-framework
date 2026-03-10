// Removed mock data imports
import { FleetInstance, Target } from "../types";

const STORAGE_KEY_API_URL = "axiom_dashboard_api_url";

const DEFAULT_API_URL = "http://localhost:5000";

export const getApiUrl = (): string => {
  const url = localStorage.getItem(STORAGE_KEY_API_URL) || DEFAULT_API_URL;
  console.debug("[axiomProvider] getApiUrl ->", url);
  return url;
};

export const setApiUrl = (url: string) => {
  localStorage.setItem(STORAGE_KEY_API_URL, url);
};

export const checkConnection = async (): Promise<boolean> => {
  const url = getApiUrl();
  if (!url) return false;
  try {
    const res = await fetch(`${url}/health`, { method: "GET" });
    return res.ok;
  } catch (e) {
    return false;
  }
};

export const fetchFleet = async (
  filter: string = "managed",
): Promise<FleetInstance[]> => {
  const url = getApiUrl();
  if (!url) {
    throw new Error("API URL not set");
  }

  try {
    const endpoint = `${url}/api/fleet?filter=${encodeURIComponent(filter)}`;
    console.debug("[axiomProvider] fetching fleet from", endpoint);
    const res = await fetch(endpoint);
    if (!res.ok) throw new Error("Failed to fetch fleet");
    const data = await res.json();
    console.debug(
      "[axiomProvider] fleet fetched, count=",
      Array.isArray(data) ? data.length : typeof data,
    );
    return data;
  } catch (error) {
    console.warn("API Error:", error);
    throw error;
  }
};

export const fetchTargets = async (): Promise<Target[]> => {
  const url = getApiUrl();
  if (!url) {
    throw new Error("API URL not set");
  }

  try {
    console.debug(
      "[axiomProvider] fetching targets from",
      `${url}/api/targets`,
    );
    const res = await fetch(`${url}/api/targets`);
    if (!res.ok) throw new Error("Failed to fetch targets: " + res.status);
    const data = await res.json();
    console.debug(
      "[axiomProvider] targets fetched, count=",
      Array.isArray(data) ? data.length : typeof data,
    );
    return data;
  } catch (error) {
    console.warn("API Error:", error);
    throw error;
  }
};
