import { Target, Vulnerability } from "../types";

/**
 * Local deterministic risk analyzer — replaces Gemini calls.
 * Keeps signatures so consumers don't need to change.
 */

const vulnWeight = (v: Vulnerability): number => {
  // Best-effort weighting based on common vulnerability fields.
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
    // Fallback: try to infer from CVSS/numeric severity
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

export const analyzeTargetRisk = async (target: Target): Promise<string> => {
  try {
    const domain = target?.domain || "unknown";
    const totalSubdomains = Array.isArray(target?.subdomains)
      ? target.subdomains.length
      : 0;
    const totalPorts =
      typeof target?.totalPorts === "number" ? target.totalPorts : 0;
    const vulns = Array.isArray(target?.vulnerabilities)
      ? target.vulnerabilities
      : [];

    // Compute a simple 0-10 risk score
    const vulnScoreRaw = vulns.reduce((acc, v) => acc + vulnWeight(v), 0);
    const vulnScore = Math.min(
      7,
      Math.round(
        (vulnScoreRaw / Math.max(1, vulns.length)) * vulns.length * 0.6
      )
    );
    const portScore = Math.min(2, Math.ceil(totalPorts / 20)); // more open ports raises risk slightly
    const subdomainScore = Math.min(1, Math.floor(totalSubdomains / 50));
    const overallScore = Math.max(
      0,
      Math.min(10, vulnScore + portScore + subdomainScore)
    );

    // Top 3 findings
    const sorted = [...vulns].sort((a, b) => vulnWeight(b) - vulnWeight(a));
    const topFindings = sorted
      .slice(0, 3)
      .map(
        (v, i) =>
          `#${i + 1} ${(v as any).name || (v as any).id || JSON.stringify(v)}`
      );

    // Fallback if no vulnerabilities
    if (topFindings.length === 0) {
      if (totalPorts > 0) {
        topFindings.push(
          `Open ports detected (${totalPorts}) — review exposed services`
        );
      } else if (totalSubdomains > 0) {
        topFindings.push(
          `Multiple subdomains (${totalSubdomains}) — inventory and check for default credentials / exposed interfaces`
        );
      } else {
        topFindings.push("No explicit findings in provided data.");
      }
    }

    // Recommended next steps (balanced for both red-team and ops)
    const recommendations = [
      "Prioritize remediation of highest-severity vulnerabilities (patch, update, or mitigate exposure).",
      "For internet-exposed services: verify authentication, apply WAF rules, and restrict access via network controls where possible.",
      "Perform targeted credentialed scanning and manual validation for top-3 findings; capture proof-of-concept safely in a controlled environment.",
    ];

    const sampleSubdomains = JSON.stringify(
      (target.subdomains || []).slice(0, 5),
      null,
      2
    );
    const vulnDetails = JSON.stringify(vulns, null, 2);

    const report = [
      `Executive Risk Report for ${domain}`,
      "",
      `Overall Risk Score (0-10): ${overallScore}`,
      `Justification: score computed from vulnerability severity distribution (${vulns.length} findings), ${totalPorts} open ports, and ${totalSubdomains} subdomains.`,
      "",
      "Top 3 Most Critical Findings:",
      topFindings.join("\n"),
      "",
      "Recommended Next Steps:",
      recommendations.join("\n"),
      "",
      "Subdomain Details (Sample):",
      sampleSubdomains,
      "",
      "Vulnerability Details:",
      vulnDetails,
    ].join("\n");

    return report;
  } catch (error) {
    console.error("Local analyzeTargetRisk error:", error);
    return "Error generating analysis.";
  }
};

export const chatWithSecurityBot = async (
  history: string[],
  newMessage: string
): Promise<string> => {
  try {
    // Minimal stateless assistant: echo intent, provide concise guidance.
    const recent = Array.isArray(history) ? history.slice(-3).join(" | ") : "";
    const trimmed = (newMessage || "").trim();
    const base = trimmed ? `Request: ${trimmed}` : "No request provided.";
    const context = recent ? `Context: ${recent}` : "";
    const advice = (() => {
      const lm = trimmed.toLowerCase();
      if (lm.includes("exploit") || lm.includes("poc")) {
        return "I cannot provide exploit code. Provide validation steps, safe proof-of-concept guidance, or mitigation advice instead.";
      }
      if (lm.includes("scan") || lm.includes("recon")) {
        return "Recommend targeted credentialed scan, then manual verification of critical findings.";
      }
      if (lm.includes("remed") || lm.includes("fix") || lm.includes("patch")) {
        return "Patch or mitigate the affected component; apply compensating controls and re-scan to verify remediation.";
      }
      return "Provide concise technical guidance, next steps, or reference checks (credentialed scan, manual validation, patching).";
    })();

    const reply = [base, context, advice].filter(Boolean).join("\n\n");
    return reply;
  } catch (error) {
    console.error("Local chatWithSecurityBot error:", error);
    return "Error communicating with local assistant.";
  }
};
