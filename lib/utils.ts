import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ── ANSI → HTML ───────────────────────────────────────────────────────────────
// Maps SGR (Select Graphic Rendition) codes to CSS colors tuned for a dark
// terminal background. Handles bold (1), standard fg (30-37), bright fg (90-97)
// and reset (0). Background codes and italic are accepted but ignored.

const _ANSI_FG: Record<number, string> = {
  30: "#6b7280", 31: "#ef4444", 32: "#22c55e", 33: "#eab308",
  34: "#60a5fa", 35: "#a855f7", 36: "#22d3ee", 37: "#d1d5db",
  90: "#9ca3af", 91: "#f87171", 92: "#4ade80", 93: "#facc15",
  94: "#818cf8", 95: "#c084fc", 96: "#67e8f9", 97: "#f9fafb",
};

/** Convert an ANSI-escape-coloured string to a safe HTML string with
 *  `<span style="…">` wrappers.  Text segments are HTML-escaped so the
 *  result is safe to set via `dangerouslySetInnerHTML`. */
export function ansiToHtml(text: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const RE = /\x1b\[([0-9;]*)m/g;
  let out = "";
  let last = 0;
  let spanOpen = false;
  let curColor = "";
  let curBold = false;

  const close = () => { if (spanOpen) { out += "</span>"; spanOpen = false; } };
  const open  = () => {
    const s = (curColor ? `color:${curColor};` : "") +
              (curBold  ? "font-weight:700;"   : "");
    if (s) { out += `<span style="${s}">`; spanOpen = true; }
  };

  let m: RegExpExecArray | null;
  while ((m = RE.exec(text)) !== null) {
    out += esc(text.slice(last, m.index));
    last = m.index + m[0].length;
    const codes = m[1] === "" ? [0] : m[1].split(";").map(Number);
    close();
    for (const c of codes) {
      if      (c === 0)        { curColor = ""; curBold = false; }
      else if (c === 1)        { curBold = true; }
      else if (_ANSI_FG[c])   { curColor = _ANSI_FG[c]; }
    }
    open();
  }
  out += esc(text.slice(last));
  close();
  return out;
}
