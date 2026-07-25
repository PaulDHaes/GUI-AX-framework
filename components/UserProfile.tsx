import React, { useState, useEffect } from "react";
import {
  User,
  Lock,
  Key,
  Copy,
  CheckCircle,
  XCircle,
  Users,
  Link as LinkIcon,
  RefreshCw,
  LogIn,
} from "lucide-react";
import type { AppUser, ProjectTeam, InviteLink } from "../types";

const API_URL = "http://localhost:5000";

// ── helpers ──────────────────────────────────────────────────────────────────

function buildInviteUrl(token: string): string {
  return `${window.location.origin}${window.location.pathname}#/invite/${token}`;
}

// ── Subcomponents ─────────────────────────────────────────────────────────────

const Section = ({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) => (
  <div className="bg-dark-800 border border-dark-700 rounded-xl p-5 space-y-4">
    <h2 className="text-sm font-semibold text-white-300 font-mono uppercase tracking-wider">
      {title}
    </h2>
    {children}
  </div>
);

const StatusBadge = ({ ok, text }: { ok: boolean; text: string }) =>
  ok ? (
    <span className="flex items-center gap-1.5 text-success-400 text-xs font-mono">
      <CheckCircle className="w-3.5 h-3.5" />
      {text}
    </span>
  ) : (
    <span className="flex items-center gap-1.5 text-danger-400 text-xs font-mono">
      <XCircle className="w-3.5 h-3.5" />
      {text}
    </span>
  );

// ── Main component ────────────────────────────────────────────────────────────

const UserProfile = () => {
  const [me, setMe] = useState<AppUser | null>(null);
  const [teams, setTeams] = useState<ProjectTeam[]>([]);
  const [invites, setInvites] = useState<InviteLink[]>([]);
  const [loadingData, setLoadingData] = useState(true);

  // Password change
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwStatus, setPwStatus] = useState<null | { ok: boolean; msg: string }>(
    null,
  );
  const [savingPw, setSavingPw] = useState(false);

  // Invite acceptance
  const [inviteToken, setInviteToken] = useState("");
  const [acceptStatus, setAcceptStatus] = useState<null | {
    ok: boolean;
    msg: string;
  }>(null);
  const [accepting, setAccepting] = useState(false);

  // Copy state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // ── Load profile data ────────────────────────────────────────────────────

  const loadData = async () => {
    setLoadingData(true);
    try {
      const [meRes, teamsRes, invitesRes] = await Promise.all([
        fetch(`${API_URL}/api/users/me`, { credentials: "include" }),
        fetch(`${API_URL}/api/teams`, { credentials: "include" }),
        fetch(`${API_URL}/api/invites/my`, { credentials: "include" }),
      ]);

      if (meRes.ok) setMe(await meRes.json());
      if (teamsRes.ok) {
        const all: ProjectTeam[] = await teamsRes.json();
        setTeams(all);
      }
      if (invitesRes.ok) setInvites(await invitesRes.json());
    } catch {
      // bridge offline — leave defaults
    } finally {
      setLoadingData(false);
    }
  };

  // Check URL hash for invite token on first load
  useEffect(() => {
    loadData();
    const hash = window.location.hash;
    const match = hash.match(/\/invite\/([a-zA-Z0-9_-]+)/);
    if (match) setInviteToken(match[1]);
  }, []);

  // ── Change password ──────────────────────────────────────────────────────

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwStatus(null);

    if (newPw.length < 8) {
      setPwStatus({
        ok: false,
        msg: "New password must be at least 8 characters.",
      });
      return;
    }
    if (newPw !== confirmPw) {
      setPwStatus({ ok: false, msg: "Passwords do not match." });
      return;
    }

    setSavingPw(true);
    try {
      const res = await fetch(`${API_URL}/api/users/me/password`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          currentPassword: currentPw,
          newPassword: newPw,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setPwStatus({ ok: true, msg: "Password changed successfully." });
        setCurrentPw("");
        setNewPw("");
        setConfirmPw("");
      } else {
        setPwStatus({
          ok: false,
          msg: data.error || "Failed to change password.",
        });
      }
    } catch {
      setPwStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setSavingPw(false);
    }
  };

  // ── Accept invite ────────────────────────────────────────────────────────

  const handleAcceptInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setAcceptStatus(null);
    if (!inviteToken.trim()) return;

    setAccepting(true);
    try {
      const res = await fetch(`${API_URL}/api/invites/accept`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: inviteToken.trim() }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setAcceptStatus({
          ok: true,
          msg: `Joined team "${data.teamName || "team"}" successfully.`,
        });
        setInviteToken("");
        // Clear invite hash from URL
        if (window.location.hash.includes("/invite/")) {
          window.history.replaceState(null, "", window.location.pathname);
        }
        await loadData();
      } else {
        setAcceptStatus({
          ok: false,
          msg: data.error || "Invalid or expired invite link.",
        });
      }
    } catch {
      setAcceptStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setAccepting(false);
    }
  };

  // ── Copy helper ──────────────────────────────────────────────────────────

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    });
  };

  // ── My teams (filtered to teams user belongs to) ────────────────────────

  const myTeams = me ? teams.filter((t) => t.memberIds?.includes(me.id)) : [];

  // ── Render ───────────────────────────────────────────────────────────────

  if (loadingData) {
    return (
      <div className="flex items-center justify-center py-32 text-white-500 text-sm font-mono">
        <RefreshCw className="w-4 h-4 animate-spin mr-2" />
        Loading profile…
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center gap-3 mb-2">
        <div className="w-10 h-10 rounded-xl bg-primary-600/20 border border-primary-500/30 flex items-center justify-center">
          <User className="w-5 h-5 text-primary-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-white font-mono">
            {me?.username ?? "Profile"}
          </h1>
          <p className="text-xs text-white-500 font-mono">
            {me?.role === "admin" ? (
              <span className="text-yellow-400">admin</span>
            ) : (
              <span className="text-primary-400">user</span>
            )}
            {me?.email ? ` · ${me.email}` : ""}
          </p>
        </div>
      </div>

      {/* Change Password */}
      <Section title="Change Password">
        <form onSubmit={handleChangePassword} className="space-y-3">
          <div>
            <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
              Current Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white-600" />
              <input
                type="password"
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                placeholder="••••••••"
                required
                autoComplete="current-password"
                className="w-full bg-dark-900 border border-dark-600 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono transition-colors"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
                New Password
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white-600" />
                <input
                  type="password"
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  placeholder="min 8 chars"
                  required
                  minLength={8}
                  autoComplete="new-password"
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono transition-colors"
                />
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
                Confirm New Password
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white-600" />
                <input
                  type="password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  placeholder="repeat password"
                  required
                  autoComplete="new-password"
                  className="w-full bg-dark-900 border border-dark-600 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono transition-colors"
                />
              </div>
            </div>
          </div>

          {pwStatus && <StatusBadge ok={pwStatus.ok} text={pwStatus.msg} />}

          <button
            type="submit"
            disabled={savingPw}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors font-mono"
          >
            {savingPw ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Lock className="w-3.5 h-3.5" />
            )}
            {savingPw ? "Saving…" : "Update Password"}
          </button>
        </form>
      </Section>

      {/* My Teams */}
      <Section title="My Project Teams">
        {myTeams.length === 0 ? (
          <p className="text-white-500 text-sm font-mono">
            You are not assigned to any project teams yet. Use an invite link
            below to join one.
          </p>
        ) : (
          <div className="space-y-2">
            {myTeams.map((team) => (
              <div
                key={team.id}
                className="flex items-center justify-between bg-dark-900 border border-dark-700 rounded-lg px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <Users className="w-4 h-4 text-primary-400 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-white font-mono">
                      {team.name}
                    </p>
                    {team.description && (
                      <p className="text-xs text-white-500 font-mono mt-0.5">
                        {team.description}
                      </p>
                    )}
                  </div>
                </div>
                <span className="text-xs text-white-600 font-mono">
                  {team.memberIds?.length ?? 0} member
                  {team.memberIds?.length !== 1 ? "s" : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* Accept Invite */}
      <Section title="Join a Team via Invite Link">
        <form onSubmit={handleAcceptInvite} className="space-y-3">
          <p className="text-xs text-white-500 font-mono">
            Paste an invite token or URL you received from an admin to join a
            project team.
          </p>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <LinkIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white-600" />
              <input
                type="text"
                value={inviteToken}
                onChange={(e) => setInviteToken(e.target.value)}
                placeholder="Invite token or URL"
                className="w-full bg-dark-900 border border-dark-600 rounded-lg pl-9 pr-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={accepting || !inviteToken.trim()}
              className="flex items-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors font-mono whitespace-nowrap"
            >
              {accepting ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <LogIn className="w-3.5 h-3.5" />
              )}
              {accepting ? "Joining…" : "Accept Invite"}
            </button>
          </div>

          {acceptStatus && (
            <StatusBadge ok={acceptStatus.ok} text={acceptStatus.msg} />
          )}
        </form>
      </Section>

      {/* Invite links shared with me */}
      {invites.length > 0 && (
        <Section title="Pending Invites">
          <div className="space-y-2">
            {invites.map((inv) => {
              const expired =
                inv.expiresAt && new Date(inv.expiresAt) < new Date();
              const used = Boolean(inv.usedBy);
              const url = buildInviteUrl(inv.token);
              return (
                <div
                  key={inv.id}
                  className="flex items-center justify-between bg-dark-900 border border-dark-700 rounded-lg px-4 py-3"
                >
                  <div>
                    <p className="text-sm font-semibold text-white font-mono">
                      {inv.teamName}
                    </p>
                    <p className="text-xs text-white-500 font-mono mt-0.5">
                      Expires {new Date(inv.expiresAt).toLocaleDateString()} ·{" "}
                      {inv.useCount}/{inv.maxUses} uses
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {expired && (
                      <span className="text-xs text-danger-400 font-mono">
                        expired
                      </span>
                    )}
                    {used && !expired && (
                      <span className="text-xs text-white-500 font-mono">
                        used
                      </span>
                    )}
                    {!expired && !used && (
                      <button
                        onClick={() => copyToClipboard(url, inv.id)}
                        className="flex items-center gap-1.5 text-xs text-white-400 hover:text-white font-mono bg-dark-700 hover:bg-dark-600 px-3 py-1.5 rounded-lg transition-colors border border-dark-600/60"
                      >
                        {copiedId === inv.id ? (
                          <CheckCircle className="w-3.5 h-3.5 text-success-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                        {copiedId === inv.id ? "Copied!" : "Copy Link"}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Section>
      )}
    </div>
  );
};

export default UserProfile;
