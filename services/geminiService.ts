import { Target, Vulnerability } from "../types";
import { getApiUrl } from "./axiomProvider";
import { getAiProvider } from "./prefs";

// ── Local deterministic risk scorer (no API key required) ────────────────────

const vulnWeight = (v: Vulnerability): number => {
  try {
    if (!v) return 1;
    const sev = (v as any).severity;
    if (typeof sev === "string") {
      const s = sev.toLowerCase();
      if (s.includes("critical")) return 5;
      if (s.includes("high")) return 4;
      if (s.includes("medium")) return 2;
      if (s.includes("low")) return 1;
    }
    const score = Number((v as any).cvss || (v as any).score || NaN);
    if (!isNaN(score)) {
      if (score >= 9) return 5;
      if (score >= 7) return 4;
      if (score >= 4) return 2;
      return 1;
    }
    return 1;
  } catch {
    return 1;
  }
};

const localRiskReport = (target: Target): string => {
  const domain = target?.domain || "unknown";
  const totalSubdomains = Array.isArray(target?.subdomains)
    ? target.subdomains.length
    : 0;
  const totalPorts =
    typeof target?.totalPorts === "number" ? target.totalPorts : 0;
  const vulns = Array.isArray(target?.vulnerabilities)
    ? target.vulnerabilities
    : [];

  const vulnScoreRaw = vulns.reduce((acc, v) => acc + vulnWeight(v), 0);
  const vulnScore = Math.min(
    7,
    Math.round(
      (vulnScoreRaw / Math.max(1, vulns.length)) * vulns.length * 0.6
    )
  );
  const portScore = Math.min(2, Math.ceil(totalPorts / 20));
  const subdomainScore = Math.min(1, Math.floor(totalSubdomains / 50));
  const overallScore = Math.max(
    0,
    Math.min(10, vulnScore + portScore + subdomainScore)
  );

  const sorted = [...vulns].sort((a, b) => vulnWeight(b) - vulnWeight(a));
  const topFindings = sorted
    .slice(0, 3)
    .map(
      (v, i) =>
        `#${i + 1} ${(v as any).name || (v as any).id || JSON.stringify(v)}`
    );

  if (topFindings.length === 0) {
    if (totalPorts > 0)
      topFindings.push(
        `Open ports detected (${totalPorts}) — review exposed services`
      );
    else if (totalSubdomains > 0)
      topFindings.push(
        `Multiple subdomains (${totalSubdomains}) — inventory and check for default credentials`
      );
    else topFindings.push("No explicit findings in provided data.");
  }

  const recommendations = [
    "Prioritize remediation of highest-severity vulnerabilities (patch, update, or mitigate exposure).",
    "For internet-exposed services: verify authentication, apply WAF rules, and restrict access via network controls where possible.",
    "Perform targeted credentialed scanning and manual validation for top-3 findings.",
  ];

  return [
    `Executive Risk Report for ${domain}`,
    "",
    `Overall Risk Score (0-10): ${overallScore}`,
    `Justification: computed from ${vulns.length} vulnerabilities, ${totalPorts} open ports, ${totalSubdomains} subdomains.`,
    "",
    "Top 3 Most Critical Findings:",
    topFindings.join("\n"),
    "",
    "Recommended Next Steps:",
    recommendations.join("\n"),
    "",
    "Subdomain Details (Sample):",
    JSON.stringify((target.subdomains || []).slice(0, 5), null, 2),
    "",
    "Vulnerability Details:",
    JSON.stringify(vulns, null, 2),
  ].join("\n");
};

// ── Bridge AI call ────────────────────────────────────────────────────────────

const callBridgeAI = async (
  prompt: string,
  provider: string
): Promise<string> => {
  const res = await fetch(`${getApiUrl()}/api/ai/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ prompt, provider }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data.response as string;
};

// ── Public API ────────────────────────────────────────────────────────────────

export const analyzeTargetRisk = async (target: Target): Promise<string> => {
  const provider = getAiProvider();

  // Local-only mode — skip the bridge call
  if (provider === "local") return localRiskReport(target);

  const domain = target?.domain || "unknown";
  const vulns = Array.isArray(target?.vulnerabilities)
    ? target.vulnerabilities
    : [];
  const totalPorts =
    typeof target?.totalPorts === "number" ? target.totalPorts : 0;
  const subdomains = Array.isArray(target?.subdomains)
    ? target.subdomains
    : [];

  const prompt = `You are a penetration testing assistant for a professional red team.

Analyze the following recon data for the target "${domain}" and provide a structured security risk report:

Target: ${domain}
Open ports: ${totalPorts}
Subdomains (${subdomains.length} total, sample of first 10): ${JSON.stringify(subdomains.slice(0, 10))}
Vulnerabilities (${vulns.length} total):
${JSON.stringify(vulns, null, 2)}

Provide:
1. Overall risk score (0-10) with justification
2. Top 3 most critical findings
3. Recommended next steps for the pentest team

Be concise and technical. Format your response in plain text (no markdown).`;

  try {
    return await callBridgeAI(prompt, provider);
  } catch (err) {
    console.warn("[AI] Bridge call failed, falling back to local analysis:", err);
    return localRiskReport(target);
  }
};

export const chatWithSecurityBot = async (
  history: string[],
  newMessage: string
): Promise<string> => {
  const provider = getAiProvider();
  const trimmed = (newMessage || "").trim();

  if (provider === "local" || !trimmed) {
    return localChat(history, trimmed);
  }

  const contextLines = history.slice(-6);
  const historyText =
    contextLines.length > 0
      ? `\n\nPrevious conversation:\n${contextLines.join("\n")}`
      : "";

  const prompt = `You are a security assistant for a penetration testing and red team. You help operators understand scan results, vulnerabilities, and remediation steps.${historyText}

Operator: ${trimmed}

Respond concisely and technically. Do not provide working exploit code.`;

  try {
    return await callBridgeAI(prompt, provider);
  } catch (err) {
    console.warn("[AI] Bridge call failed, falling back to local chat:", err);
    return localChat(history, trimmed);
  }
};

// ── Local chat fallback ───────────────────────────────────────────────────────

const localChat = (history: string[], message: string): string => {
  try {
    const recent = Array.isArray(history) ? history.slice(-3).join(" | ") : "";
    const base = message ? `Request: ${message}` : "No request provided.";
    const context = recent ? `Context: ${recent}` : "";
    const lm = message.toLowerCase();
    const advice = (() => {
      if (lm.includes("exploit") || lm.includes("poc"))
        return "I cannot provide exploit code. Provide validation steps, safe proof-of-concept guidance, or mitigation advice instead.";
      if (lm.includes("scan") || lm.includes("recon"))
        return "Recommend targeted credentialed scan, then manual verification of critical findings.";
      if (lm.includes("remed") || lm.includes("fix") || lm.includes("patch"))
        return "Patch or mitigate the affected component; apply compensating controls and re-scan to verify remediation.";
      return "Provide concise technical guidance, next steps, or reference checks (credentialed scan, manual validation, patching).";
    })();
    return [base, context, advice].filter(Boolean).join("\n\n");
  } catch {
    return "Error communicating with local assistant.";
  }
};
