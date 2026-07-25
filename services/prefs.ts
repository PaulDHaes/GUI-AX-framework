// Client-side user preferences persisted in localStorage.
// Kept in one place so every component reads/writes the same keys.

const ONLINE_GEO_KEY = "axmap:onlineGeo:v1";

/**
 * Whether the online IP-geolocation provider (ip-api.com) may be used on the
 * Geo Map. Defaults to enabled. When off, the "Online" lookup button is hidden
 * so target IPs are never sent to a third party.
 */
export function getOnlineGeoEnabled(): boolean {
  try {
    return localStorage.getItem(ONLINE_GEO_KEY) !== "0";
  } catch {
    return true;
  }
}

export function setOnlineGeoEnabled(enabled: boolean): void {
  try {
    localStorage.setItem(ONLINE_GEO_KEY, enabled ? "1" : "0");
  } catch {
    /* ignore quota / unavailable storage */
  }
}
