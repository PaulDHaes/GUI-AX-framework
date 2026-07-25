import React, { useState } from "react";
import { Lock, User, AlertCircle, Loader2 } from "lucide-react";
import BinocularsSkullLogo from "./ui/BinocularsSkullLogo";

interface LoginPageProps {
  apiUrl: string;
  onSuccess: (token: string) => void;
}

const LoginPage = ({ apiUrl, onSuccess }: LoginPageProps) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${apiUrl}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (res.ok) {
        const data = await res.json();
        onSuccess(data.token || "");
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || "Invalid credentials");
      }
    } catch {
      setError("Could not reach the server. Is the bridge running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-900 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <BinocularsSkullLogo className="w-16 h-16 mb-4 text-primary-400" />
          <h1 className="text-2xl font-bold text-white font-mono tracking-tight">
            GUI-AX
          </h1>
          <p className="text-white-500 text-sm mt-1 font-mono">
            axiom dashboard
          </p>
        </div>

        {/* Card */}
        <div className="bg-dark-800 border border-dark-700 rounded-2xl p-6 shadow-2xl">
          <p className="text-xs font-semibold text-white-500 uppercase tracking-wider mb-5 font-mono">
            Sign in to continue
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username */}
            <div>
              <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white-600" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  required
                  autoFocus
                  autoComplete="username"
                  className="w-full bg-dark-900 border border-dark-600 rounded-xl pl-9 pr-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono transition-colors"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-[11px] font-mono text-white-600 mb-1.5 uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white-600" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                  className="w-full bg-dark-900 border border-dark-600 rounded-xl pl-9 pr-3 py-2.5 text-sm text-white placeholder-zinc-700 focus:outline-none focus:border-primary-500/60 font-mono transition-colors"
                />
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-primary-600 hover:bg-primary-500 active:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl py-2.5 text-sm transition-colors flex items-center justify-center gap-2 mt-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Signing in…
                </>
              ) : (
                "Sign in"
              )}
            </button>
          </form>
        </div>

        {/* Hint */}
        <p className="text-center text-[11px] text-white-700 mt-5 font-mono">
          Set{" "}
          <span className="text-white-500 bg-dark-800 px-1.5 py-0.5 rounded font-mono">
            GUI_AX_PASSWORD
          </span>{" "}
          env var to enable this gate
        </p>
      </div>
    </div>
  );
};

export default LoginPage;
