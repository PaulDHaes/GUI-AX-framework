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

// ── Theme (light = Nintendo chrome per DESIGN.md, dark = original cyberpunk) ──

const THEME_KEY = "axmap:theme:v1";
export type Theme = "light" | "dark";

export function getTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* ignore */
  }
  return "light"; // Nintendo chrome is the new default theme
}

/** Applies the theme's `.dark` class to <html> and persists the choice. */
export function applyTheme(theme: Theme): void {
  const html = document.documentElement;
  html.classList.add("theme-transitioning");
  html.classList.toggle("dark", theme === "dark");
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* ignore quota / unavailable storage */
  }
  setTimeout(() => html.classList.remove("theme-transitioning"), 1100);
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  return next;
}

// ── AI provider preference ────────────────────────────────────────────────────

const AI_PROVIDER_KEY = "axmap:aiProvider:v1";
export type AiProvider = "auto" | "ollama" | "claude" | "local";

export function getAiProvider(): AiProvider {
  try {
    const stored = localStorage.getItem(AI_PROVIDER_KEY);
    if (
      stored === "auto" ||
      stored === "ollama" ||
      stored === "claude" ||
      stored === "local"
    )
      return stored;
  } catch {
    /* ignore */
  }
  return "auto";
}

export function setAiProvider(p: AiProvider): void {
  try {
    localStorage.setItem(AI_PROVIDER_KEY, p);
  } catch {
    /* ignore */
  }
}
