import React, { useState, useEffect, useCallback } from "react";
import {
  Users,
  UserPlus,
  Trash2,
  Key,
  Copy,
  CheckCircle,
  XCircle,
  RefreshCw,
  Shield,
  Link as LinkIcon,
  Plus,
  Edit2,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import type { AppUser, ProjectTeam, InviteLink } from "../types";

const API_URL = "http://localhost:5000";

// ── helpers ──────────────────────────────────────────────────────────────────

function buildInviteUrl(token: string): string {
  return `${window.location.origin}${window.location.pathname}#/invite/${token}`;
}

function fmtDate(s?: string): string {
  if (!s) return "—";
  return new Date(s).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

// ── Sub-components ────────────────────────────────────────────────────────────

const TabButton = ({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) => (
  <button
    onClick={onClick}
    className={`px-4 py-2 text-sm font-mono rounded-lg transition-colors ${
      active
        ? "bg-primary-600/30 text-primary-300 border border-primary-500/40"
        : "text-white-400 hover:text-white hover:bg-dark-700/50"
    }`}
  >
    {children}
  </button>
);

const RoleBadge = ({ role }: { role: string }) =>
  role === "admin" ? (
    <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
      <Shield className="w-3 h-3" />
      admin
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-primary-500/10 text-primary-400 border border-primary-500/20">
      user
    </span>
  );

// ── Modal wrapper ─────────────────────────────────────────────────────────────

const Modal = ({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
    <div className="bg-dark-800 border border-dark-700 rounded-xl w-full max-w-md shadow-2xl">
      <div className="flex items-center justify-between px-5 py-4 border-b border-dark-700">
        <span className="text-sm font-bold text-white font-mono">{title}</span>
        <button
          onClick={onClose}
          className="text-white-400 hover:text-white transition-colors text-lg leading-none"
        >
          ✕
        </button>
      </div>
      <div className="p-5">{children}</div>
    </div>
  </div>
);

// ── StatusMsg ─────────────────────────────────────────────────────────────────

const StatusMsg = ({
  status,
}: {
  status: { ok: boolean; msg: string } | null;
}) => {
  if (!status) return null;
  return status.ok ? (
    <span className="flex items-center gap-1.5 text-success-400 text-xs font-mono">
      <CheckCircle className="w-3.5 h-3.5" />
      {status.msg}
    </span>
  ) : (
    <span className="flex items-center gap-1.5 text-danger-400 text-xs font-mono">
      <XCircle className="w-3.5 h-3.5" />
      {status.msg}
    </span>
  );
};

// ── AdminPanel ────────────────────────────────────────────────────────────────

const AdminPanel = () => {
  const [tab, setTab] = useState<"users" | "teams" | "invites">("users");
  const [users, setUsers] = useState<AppUser[]>([]);
  const [teams, setTeams] = useState<ProjectTeam[]>([]);
  const [invites, setInvites] = useState<InviteLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Modals
  const [createUserOpen, setCreateUserOpen] = useState(false);
  const [resetPwUser, setResetPwUser] = useState<AppUser | null>(null);
  const [assignTeamUser, setAssignTeamUser] = useState<AppUser | null>(null);
  const [createTeamOpen, setCreateTeamOpen] = useState(false);
  const [createInviteOpen, setCreateInviteOpen] = useState(false);

  // ── Load data ──────────────────────────────────────────────────────────

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [uRes, tRes, iRes] = await Promise.all([
        fetch(`${API_URL}/api/users`, { credentials: "include" }),
        fetch(`${API_URL}/api/teams`, { credentials: "include" }),
        fetch(`${API_URL}/api/invites`, { credentials: "include" }),
      ]);
      if (uRes.ok) setUsers(await uRes.json());
      if (tRes.ok) setTeams(await tRes.json());
      if (iRes.ok) setInvites(await iRes.json());
    } catch {
      // bridge offline
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  // ── Copy helper ────────────────────────────────────────────────────────

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    });
  };

  // ── Delete user ────────────────────────────────────────────────────────

  const deleteUser = async (user: AppUser) => {
    if (
      !window.confirm(`Delete user "${user.username}"? This cannot be undone.`)
    )
      return;
    try {
      const res = await fetch(`${API_URL}/api/users/${user.id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (res.ok) setUsers((prev) => prev.filter((u) => u.id !== user.id));
    } catch {}
  };

  // ── Toggle role ────────────────────────────────────────────────────────

  const toggleRole = async (user: AppUser) => {
    const newRole = user.role === "admin" ? "user" : "admin";
    try {
      const res = await fetch(`${API_URL}/api/users/${user.id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: newRole }),
      });
      if (res.ok)
        setUsers((prev) =>
          prev.map((u) => (u.id === user.id ? { ...u, role: newRole } : u)),
        );
    } catch {}
  };

  // ── Revoke invite ──────────────────────────────────────────────────────

  const revokeInvite = async (inv: InviteLink) => {
    if (!window.confirm("Revoke this invite link?")) return;
    try {
      const res = await fetch(`${API_URL}/api/invites/${inv.id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (res.ok) setInvites((prev) => prev.filter((i) => i.id !== inv.id));
    } catch {}
  };

  // ── Delete team ────────────────────────────────────────────────────────

  const deleteTeam = async (team: ProjectTeam) => {
    if (!window.confirm(`Delete team "${team.name}"?`)) return;
    try {
      const res = await fetch(`${API_URL}/api/teams/${team.id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (res.ok) setTeams((prev) => prev.filter((t) => t.id !== team.id));
    } catch {}
  };

  // ── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="max-w-5xl mx-auto space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-yellow-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white font-mono">
              Admin Panel
            </h1>
            <p className="text-xs text-white-500 font-mono">
              Manage users, teams & invites
            </p>
          </div>
        </div>
        <button
          onClick={loadAll}
          disabled={loading}
          className="flex items-center gap-1.5 text-xs text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 border border-dark-600/60 px-3 py-2 rounded-lg font-mono transition-colors disabled:opacity-50"
        >
          <RefreshCw
            className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        <TabButton active={tab === "users"} onClick={() => setTab("users")}>
          Users ({users.length})
        </TabButton>
        <TabButton active={tab === "teams"} onClick={() => setTab("teams")}>
          Teams ({teams.length})
        </TabButton>
        <TabButton active={tab === "invites"} onClick={() => setTab("invites")}>
          Invite Links ({invites.length})
        </TabButton>
      </div>

      {/* ── Users tab ── */}
      {tab === "users" && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-dark-700">
            <span className="text-xs font-mono text-white-500 uppercase tracking-wider">
              All Users
            </span>
            <button
              onClick={() => setCreateUserOpen(true)}
              className="flex items-center gap-1.5 text-xs text-white bg-primary-600 hover:bg-primary-500 px-3 py-1.5 rounded-lg font-mono transition-colors"
            >
              <UserPlus className="w-3.5 h-3.5" />
              New User
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16 text-white-500 text-sm font-mono gap-2">
              <RefreshCw className="w-4 h-4 animate-spin" />
              Loading…
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-16 text-white-500 text-sm font-mono">
              No users found.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700 text-[11px] text-white-600 uppercase tracking-wider font-mono">
                  <th className="px-5 py-2.5 text-left">Username</th>
                  <th className="px-5 py-2.5 text-left">Email</th>
                  <th className="px-5 py-2.5 text-left">Role</th>
                  <th className="px-5 py-2.5 text-left">Teams</th>
                  <th className="px-5 py-2.5 text-left">Last Login</th>
                  <th className="px-5 py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user, idx) => (
                  <tr
                    key={user.id}
                    className={`border-b border-dark-700/50 hover:bg-dark-700/20 transition-colors ${
                      idx === users.length - 1 ? "border-b-0" : ""
                    }`}
                  >
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-primary-600/20 border border-primary-500/30 flex items-center justify-center flex-shrink-0">
                          <span className="text-[10px] font-bold text-primary-300 uppercase">
                            {user.username[0]}
                          </span>
                        </div>
                        <span className="text-white font-mono font-semibold">
                          {user.username}
                        </span>
                        {!user.active && (
                          <span className="text-[11px] text-white-600 font-mono">
                            (inactive)
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-3.5 text-white-400 font-mono text-xs">
                      {user.email || "—"}
                    </td>
                    <td className="px-5 py-3.5">
                      <RoleBadge role={user.role} />
                    </td>
                    <td className="px-5 py-3.5 text-white-400 font-mono text-xs">
                      {user.teams?.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {user.teams.map((tid) => {
                            const team = teams.find((t) => t.id === tid);
                            return (
                              <span
                                key={tid}
                                className="px-1.5 py-0.5 bg-dark-700 border border-dark-600 rounded text-[11px] font-mono"
                              >
                                {team?.name ?? tid}
                              </span>
                            );
                          })}
                        </div>
                      ) : (
                        <span className="text-white-600">none</span>
                      )}
                    </td>
                    <td className="px-5 py-3.5 text-white-500 font-mono text-xs">
                      {fmtDate(user.lastLogin)}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setAssignTeamUser(user)}
                          title="Assign to team"
                          className="p-1.5 text-white-500 hover:text-primary-300 hover:bg-primary-500/10 rounded transition-colors"
                        >
                          <Users className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => toggleRole(user)}
                          title={`Make ${user.role === "admin" ? "user" : "admin"}`}
                          className="p-1.5 text-white-500 hover:text-yellow-300 hover:bg-yellow-500/10 rounded transition-colors"
                        >
                          <Shield className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setResetPwUser(user)}
                          title="Reset password"
                          className="p-1.5 text-white-500 hover:text-cyan-300 hover:bg-cyan-500/10 rounded transition-colors"
                        >
                          <Key className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => deleteUser(user)}
                          title="Delete user"
                          className="p-1.5 text-white-500 hover:text-danger-400 hover:bg-danger-500/10 rounded transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Teams tab ── */}
      {tab === "teams" && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-dark-700">
            <span className="text-xs font-mono text-white-500 uppercase tracking-wider">
              Project Teams
            </span>
            <button
              onClick={() => setCreateTeamOpen(true)}
              className="flex items-center gap-1.5 text-xs text-white bg-primary-600 hover:bg-primary-500 px-3 py-1.5 rounded-lg font-mono transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              New Team
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16 text-white-500 text-sm font-mono gap-2">
              <RefreshCw className="w-4 h-4 animate-spin" />
              Loading…
            </div>
          ) : teams.length === 0 ? (
            <div className="text-center py-16 text-white-500 text-sm font-mono">
              No teams yet. Create one to get started.
            </div>
          ) : (
            <div className="divide-y divide-dark-700/50">
              {teams.map((team) => {
                const members = users.filter((u) =>
                  team.memberIds?.includes(u.id),
                );
                return (
                  <div key={team.id} className="px-5 py-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-sm font-bold text-white font-mono">
                          {team.name}
                        </p>
                        {team.description && (
                          <p className="text-xs text-white-500 font-mono mt-0.5">
                            {team.description}
                          </p>
                        )}
                        <div className="flex items-center gap-3 mt-2 text-xs text-white-600 font-mono">
                          <span>
                            {members.length} member
                            {members.length !== 1 ? "s" : ""}
                          </span>
                          <span>·</span>
                          <span>
                            {team.targetIds?.length ?? 0} target
                            {team.targetIds?.length !== 1 ? "s" : ""}
                          </span>
                          <span>·</span>
                          <span>Created {fmtDate(team.createdAt)}</span>
                        </div>
                        {members.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 mt-2">
                            {members.map((m) => (
                              <span
                                key={m.id}
                                className="inline-flex items-center gap-1 text-[11px] bg-dark-700 border border-dark-600 text-white-300 px-2 py-0.5 rounded font-mono"
                              >
                                {m.username}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setCreateInviteOpen(true)}
                          title="Create invite link for this team"
                          className="flex items-center gap-1.5 text-xs text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 border border-dark-600/60 px-3 py-1.5 rounded-lg font-mono transition-colors"
                          data-team-id={team.id}
                        >
                          <LinkIcon className="w-3.5 h-3.5" />
                          Invite
                        </button>
                        <button
                          onClick={() => deleteTeam(team)}
                          className="p-1.5 text-white-500 hover:text-danger-400 hover:bg-danger-500/10 rounded transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Invites tab ── */}
      {tab === "invites" && (
        <div className="bg-dark-800 border border-dark-700 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-dark-700">
            <span className="text-xs font-mono text-white-500 uppercase tracking-wider">
              Invite Links
            </span>
            <button
              onClick={() => setCreateInviteOpen(true)}
              className="flex items-center gap-1.5 text-xs text-white bg-primary-600 hover:bg-primary-500 px-3 py-1.5 rounded-lg font-mono transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Create Invite
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16 text-white-500 text-sm font-mono gap-2">
              <RefreshCw className="w-4 h-4 animate-spin" />
              Loading…
            </div>
          ) : invites.length === 0 ? (
            <div className="text-center py-16 text-white-500 text-sm font-mono">
              No invite links yet.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-dark-700 text-[11px] text-white-600 uppercase tracking-wider font-mono">
                  <th className="px-5 py-2.5 text-left">Team</th>
                  <th className="px-5 py-2.5 text-left">Created By</th>
                  <th className="px-5 py-2.5 text-left">Expires</th>
                  <th className="px-5 py-2.5 text-left">Uses</th>
                  <th className="px-5 py-2.5 text-left">Status</th>
                  <th className="px-5 py-2.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {invites.map((inv, idx) => {
                  const expired =
                    inv.expiresAt && new Date(inv.expiresAt) < new Date();
                  const exhausted = inv.useCount >= inv.maxUses;
                  const active = !expired && !exhausted;
                  const invUrl = buildInviteUrl(inv.token);
                  return (
                    <tr
                      key={inv.id}
                      className={`border-b border-dark-700/50 hover:bg-dark-700/20 transition-colors ${
                        idx === invites.length - 1 ? "border-b-0" : ""
                      }`}
                    >
                      <td className="px-5 py-3.5 text-white font-mono font-semibold">
                        {inv.teamName}
                      </td>
                      <td className="px-5 py-3.5 text-white-400 font-mono text-xs">
                        {inv.createdBy}
                      </td>
                      <td className="px-5 py-3.5 text-white-400 font-mono text-xs">
                        {fmtDate(inv.expiresAt)}
                      </td>
                      <td className="px-5 py-3.5 text-white-400 font-mono text-xs">
                        {inv.useCount}/{inv.maxUses}
                      </td>
                      <td className="px-5 py-3.5">
                        {active ? (
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-success-500/10 text-success-400 border border-success-500/20">
                            active
                          </span>
                        ) : expired ? (
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-dark-700 text-white-500 border border-dark-600">
                            expired
                          </span>
                        ) : (
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-dark-700 text-white-500 border border-dark-600">
                            exhausted
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="flex items-center justify-end gap-2">
                          {active && (
                            <button
                              onClick={() => copyToClipboard(invUrl, inv.id)}
                              title="Copy invite URL"
                              className="flex items-center gap-1.5 text-xs text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 border border-dark-600/60 px-3 py-1.5 rounded-lg font-mono transition-colors"
                            >
                              {copiedId === inv.id ? (
                                <CheckCircle className="w-3.5 h-3.5 text-success-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                              {copiedId === inv.id ? "Copied!" : "Copy Link"}
                            </button>
                          )}
                          <button
                            onClick={() => revokeInvite(inv)}
                            title="Revoke invite"
                            className="p-1.5 text-white-500 hover:text-danger-400 hover:bg-danger-500/10 rounded transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Modals ── */}

      {/* Create User */}
      {createUserOpen && (
        <CreateUserModal
          onClose={() => setCreateUserOpen(false)}
          onCreated={(u) => {
            setUsers((prev) => [...prev, u]);
            setCreateUserOpen(false);
          }}
        />
      )}

      {/* Reset Password */}
      {resetPwUser && (
        <ResetPasswordModal
          user={resetPwUser}
          onClose={() => setResetPwUser(null)}
        />
      )}

      {/* Assign Team */}
      {assignTeamUser && (
        <AssignTeamModal
          user={assignTeamUser}
          teams={teams}
          onClose={() => setAssignTeamUser(null)}
          onUpdated={(userId, teamIds) => {
            setUsers((prev) =>
              prev.map((u) => (u.id === userId ? { ...u, teams: teamIds } : u)),
            );
            setAssignTeamUser(null);
          }}
        />
      )}

      {/* Create Team */}
      {createTeamOpen && (
        <CreateTeamModal
          onClose={() => setCreateTeamOpen(false)}
          onCreated={(t) => {
            setTeams((prev) => [...prev, t]);
            setCreateTeamOpen(false);
          }}
        />
      )}

      {/* Create Invite */}
      {createInviteOpen && (
        <CreateInviteModal
          teams={teams}
          onClose={() => setCreateInviteOpen(false)}
          onCreated={(inv) => {
            setInvites((prev) => [...prev, inv]);
            setCreateInviteOpen(false);
            setTab("invites");
          }}
        />
      )}
    </div>
  );
};

// ── Create User Modal ─────────────────────────────────────────────────────────

const CreateUserModal = ({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (u: AppUser) => void;
}) => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"user" | "admin">("user");
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus(null);
    if (password.length < 8) {
      setStatus({ ok: false, msg: "Password must be at least 8 characters." });
      return;
    }
    setSaving(true);
    try {
      const res = await fetch(`${API_URL}/api/users`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password, role }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        onCreated(data);
      } else {
        setStatus({ ok: false, msg: data.error || "Failed to create user." });
      }
    } catch {
      setStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Create New User" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Username
          </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            placeholder="johndoe"
            autoFocus
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Email (optional)
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="john@example.com"
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            placeholder="min 8 characters"
            autoComplete="new-password"
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Role
          </label>
          <div className="flex gap-3">
            {(["user", "admin"] as const).map((r) => (
              <label
                key={r}
                className="flex items-center gap-2 cursor-pointer text-sm text-white-300 font-mono"
              >
                <input
                  type="radio"
                  name="role"
                  value={r}
                  checked={role === r}
                  onChange={() => setRole(r)}
                  className="accent-primary-500"
                />
                {r}
              </label>
            ))}
          </div>
        </div>
        <StatusMsg status={status} />
        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={saving}
            className="flex-1 flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors font-mono"
          >
            {saving ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <UserPlus className="w-3.5 h-3.5" />
            )}
            {saving ? "Creating…" : "Create User"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 text-sm text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 rounded-lg font-mono transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
};

// ── Reset Password Modal ──────────────────────────────────────────────────────

const ResetPasswordModal = ({
  user,
  onClose,
}: {
  user: AppUser;
  onClose: () => void;
}) => {
  const [newPw, setNewPw] = useState("");
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatus(null);
    if (newPw.length < 8) {
      setStatus({ ok: false, msg: "Password must be at least 8 characters." });
      return;
    }
    setSaving(true);
    try {
      const res = await fetch(`${API_URL}/api/users/${user.id}/password`, {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ newPassword: newPw }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setStatus({ ok: true, msg: "Password reset successfully." });
        setNewPw("");
      } else {
        setStatus({
          ok: false,
          msg: data.error || "Failed to reset password.",
        });
      }
    } catch {
      setStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={`Reset Password — ${user.username}`} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <p className="text-xs text-white-500 font-mono">
          Set a new password for{" "}
          <span className="text-white">{user.username}</span>. The user will
          need to log in again with the new password.
        </p>
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            New Password
          </label>
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            required
            minLength={8}
            placeholder="min 8 characters"
            autoFocus
            autoComplete="new-password"
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono"
          />
        </div>
        <StatusMsg status={status} />
        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={saving}
            className="flex-1 flex items-center justify-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors font-mono"
          >
            {saving ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Key className="w-3.5 h-3.5" />
            )}
            {saving ? "Saving…" : "Reset Password"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 text-sm text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 rounded-lg font-mono transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
};

// ── Assign Team Modal ─────────────────────────────────────────────────────────

const AssignTeamModal = ({
  user,
  teams,
  onClose,
  onUpdated,
}: {
  user: AppUser;
  teams: ProjectTeam[];
  onClose: () => void;
  onUpdated: (userId: string, teamIds: string[]) => void;
}) => {
  const [selected, setSelected] = useState<string[]>(user.teams ?? []);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);

  const toggle = (tid: string) =>
    setSelected((prev) =>
      prev.includes(tid) ? prev.filter((id) => id !== tid) : [...prev, tid],
    );

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setStatus(null);
    try {
      const res = await fetch(`${API_URL}/api/users/${user.id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ teams: selected }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        onUpdated(user.id, selected);
      } else {
        setStatus({ ok: false, msg: data.error || "Failed to update teams." });
      }
    } catch {
      setStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={`Assign Teams — ${user.username}`} onClose={onClose}>
      <form onSubmit={handleSave} className="space-y-4">
        {teams.length === 0 ? (
          <p className="text-white-500 text-sm font-mono">
            No teams available. Create a team first.
          </p>
        ) : (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {teams.map((team) => (
              <label
                key={team.id}
                className="flex items-center gap-3 cursor-pointer bg-dark-900 border border-dark-700 rounded-lg px-4 py-3 hover:bg-dark-700/30 transition-colors"
              >
                <input
                  type="checkbox"
                  checked={selected.includes(team.id)}
                  onChange={() => toggle(team.id)}
                  className="accent-primary-500 w-4 h-4"
                />
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
              </label>
            ))}
          </div>
        )}
        <StatusMsg status={status} />
        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={saving || teams.length === 0}
            className="flex-1 flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors font-mono"
          >
            {saving ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Users className="w-3.5 h-3.5" />
            )}
            {saving ? "Saving…" : "Save Assignments"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 text-sm text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 rounded-lg font-mono transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
};

// ── Create Team Modal ─────────────────────────────────────────────────────────

const CreateTeamModal = ({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (t: ProjectTeam) => void;
}) => {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setStatus(null);
    try {
      const res = await fetch(`${API_URL}/api/teams`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        onCreated(data);
      } else {
        setStatus({ ok: false, msg: data.error || "Failed to create team." });
      }
    } catch {
      setStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Create Project Team" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Team Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="Red Team Alpha"
            autoFocus
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono"
          />
        </div>
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Description (optional)
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Briefly describe this team's focus…"
            rows={2}
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono resize-none"
          />
        </div>
        <StatusMsg status={status} />
        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={saving}
            className="flex-1 flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors font-mono"
          >
            {saving ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Plus className="w-3.5 h-3.5" />
            )}
            {saving ? "Creating…" : "Create Team"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 text-sm text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 rounded-lg font-mono transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
};

// ── Create Invite Modal ───────────────────────────────────────────────────────

const CreateInviteModal = ({
  teams,
  onClose,
  onCreated,
}: {
  teams: ProjectTeam[];
  onClose: () => void;
  onCreated: (inv: InviteLink) => void;
}) => {
  const [teamId, setTeamId] = useState(teams[0]?.id ?? "");
  const [maxUses, setMaxUses] = useState(5);
  const [expiryDays, setExpiryDays] = useState(7);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);
  const [createdInvite, setCreatedInvite] = useState<InviteLink | null>(null);
  const [copiedCreated, setCopiedCreated] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!teamId) {
      setStatus({ ok: false, msg: "Please select a team." });
      return;
    }
    setSaving(true);
    setStatus(null);
    try {
      const res = await fetch(`${API_URL}/api/invites`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ teamId, maxUses, expiryDays }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setCreatedInvite(data);
        onCreated(data);
      } else {
        setStatus({ ok: false, msg: data.error || "Failed to create invite." });
      }
    } catch {
      setStatus({ ok: false, msg: "Could not reach the server." });
    } finally {
      setSaving(false);
    }
  };

  if (createdInvite) {
    const url = buildInviteUrl(createdInvite.token);
    return (
      <Modal title="Invite Link Created" onClose={onClose}>
        <div className="space-y-4">
          <div className="bg-success-500/10 border border-success-500/20 rounded-lg px-4 py-3 flex items-start gap-2">
            <CheckCircle className="w-4 h-4 text-success-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-success-300 font-mono">
              Invite link created for team{" "}
              <span className="font-bold">{createdInvite.teamName}</span>. Share
              this link with the user.
            </p>
          </div>
          <div className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-3">
            <p className="text-xs text-white-500 font-mono mb-2 uppercase tracking-wider">
              Invite URL
            </p>
            <p className="text-xs text-cyan-300 font-mono break-all select-all">
              {url}
            </p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => {
                navigator.clipboard.writeText(url).then(() => {
                  setCopiedCreated(true);
                  setTimeout(() => setCopiedCreated(false), 2000);
                });
              }}
              className="flex-1 flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 text-white px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors font-mono"
            >
              {copiedCreated ? (
                <CheckCircle className="w-3.5 h-3.5 text-success-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              {copiedCreated ? "Copied!" : "Copy Link"}
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2.5 text-sm text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 rounded-lg font-mono transition-colors"
            >
              Done
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Create Invite Link" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
            Project Team
          </label>
          {teams.length === 0 ? (
            <p className="text-danger-400 text-xs font-mono">
              No teams exist yet. Create a team first.
            </p>
          ) : (
            <select
              value={teamId}
              onChange={(e) => setTeamId(e.target.value)}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500/60 font-mono"
            >
              {teams.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
              Max Uses
            </label>
            <input
              type="number"
              value={maxUses}
              onChange={(e) => setMaxUses(Math.max(1, Number(e.target.value)))}
              min={1}
              max={100}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500/60 font-mono"
            />
          </div>
          <div>
            <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
              Expires (days)
            </label>
            <input
              type="number"
              value={expiryDays}
              onChange={(e) =>
                setExpiryDays(Math.max(1, Number(e.target.value)))
              }
              min={1}
              max={365}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none focus:border-primary-500/60 font-mono"
            />
          </div>
        </div>
        <StatusMsg status={status} />
        <div className="flex gap-3 pt-1">
          <button
            type="submit"
            disabled={saving || teams.length === 0}
            className="flex-1 flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors font-mono"
          >
            {saving ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <LinkIcon className="w-3.5 h-3.5" />
            )}
            {saving ? "Creating…" : "Generate Invite Link"}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2.5 text-sm text-white-400 hover:text-white bg-dark-700 hover:bg-dark-600 rounded-lg font-mono transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
};

export default AdminPanel;
