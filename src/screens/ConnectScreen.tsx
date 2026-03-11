import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Eye, EyeOff, Loader2, Settings, Wifi, WifiOff, Trash2, Wrench, ArrowUp, ArrowDown, LogOut } from "lucide-react";
import wedimaLogo from "../assets/wedima-logo.svg";

interface Props {
  isConnected: boolean;
  connectionName?: string | null;
  onStatusChange: () => void;
  onReset: () => void;
}

interface Stats {
  bytes_tx: number;
  bytes_rx: number;
  connection_name: string | null;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export default function ConnectScreen({ isConnected, connectionName, onStatusChange, onReset }: Props) {
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showUninstallConfirm, setShowUninstallConfirm] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const settingsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (settingsRef.current && !settingsRef.current.contains(e.target as Node)) {
        setShowSettings(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  useEffect(() => {
    if (!isConnected) {
      setStats(null);
      return;
    }
    const poll = async () => {
      try {
        const s = await invoke<Stats>("get_stats");
        setStats(s);
      } catch {}
    };
    poll();
    const id = setInterval(poll, 1000);
    return () => clearInterval(id);
  }, [isConnected]);

  const handleConnect = async () => {
    if (!password) return setError("Please enter your connection password.");
    setLoading(true);
    setError(null);
    try {
      await invoke("connect", { password });
      setPassword("");
      onStatusChange();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnect = async () => {
    setLoading(true);
    setError(null);
    try {
      await invoke("disconnect");
      onStatusChange();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    setShowDeleteConfirm(false);
    await onReset();
  };

  const handleUninstallHelper = async () => {
    setShowUninstallConfirm(false);
    setLoading(true);
    setError(null);
    try {
      await invoke("uninstall_helper");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen flex-col bg-bg">
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div className="flex flex-col justify-center">
          <img src={wedimaLogo} alt="Wedima VPN WG" className="h-5 brightness-0 invert" />
          {connectionName && (
            <div className="mt-0.5 text-xs text-text-muted">{connectionName}</div>
          )}
        </div>
        <div className="relative" ref={settingsRef}>
          <button
            onClick={() => setShowSettings((v) => !v)}
            className="rounded-md p-1.5 text-text-muted transition-colors hover:bg-surface hover:text-text-main"
            title="Settings"
          >
            <Settings className="h-4 w-4" />
          </button>
          {showSettings && (
            <div className="absolute right-0 top-full z-50 mt-1 min-w-[200px] rounded-lg border border-border bg-surface shadow-xl">
              <button
                onClick={() => { setShowSettings(false); setShowDeleteConfirm(true); }}
                className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm text-danger transition-colors hover:bg-danger/10"
              >
                <Trash2 className="h-4 w-4 shrink-0" />
                Delete Connection
              </button>
              <div className="border-t border-border" />
              <button
                onClick={() => { setShowSettings(false); setShowUninstallConfirm(true); }}
                className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm text-text-muted transition-colors hover:bg-surface hover:text-text-main"
              >
                <Wrench className="h-4 w-4 shrink-0" />
                Uninstall Helper
              </button>
              <div className="border-t border-border" />
              <button
                onClick={() => { setShowSettings(false); invoke("quit_app"); }}
                className="flex w-full items-center gap-3 px-4 py-3 text-left text-sm text-text-muted transition-colors hover:bg-surface hover:text-text-main"
              >
                <LogOut className="h-4 w-4 shrink-0" />
                Quit Application
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="flex flex-1 flex-col items-center justify-center px-8">
        <div className="mb-8 flex flex-col items-center gap-4">
          <div
            className={`relative flex h-24 w-24 items-center justify-center rounded-full border-2 transition-all duration-500 ${
              isConnected
                ? "border-primary bg-primary/10"
                : "border-border bg-surface"
            }`}
          >
            {isConnected && (
              <span className="absolute inset-0 animate-ping rounded-full bg-primary/20" />
            )}
            {isConnected ? (
              <Wifi className="h-10 w-10 text-primary" />
            ) : (
              <WifiOff className="h-10 w-10 text-text-muted" />
            )}
          </div>

          <div className="text-center">
            <div
              className={`mb-1 flex items-center justify-center gap-2 text-lg font-semibold ${
                isConnected ? "text-primary" : "text-text-muted"
              }`}
            >
              <span
                className={`inline-block h-2 w-2 rounded-full ${
                  isConnected ? "bg-primary" : "bg-text-muted"
                }`}
              />
              {isConnected ? "Connected" : "Disconnected"}
            </div>
            {isConnected && stats ? (
              <div className="mt-1 flex items-center justify-center gap-4 text-xs text-text-muted">
                <span className="flex items-center gap-1">
                  <ArrowUp className="h-3 w-3 text-primary" />
                  {formatBytes(stats.bytes_tx)}
                </span>
                <span className="flex items-center gap-1">
                  <ArrowDown className="h-3 w-3 text-primary" />
                  {formatBytes(stats.bytes_rx)}
                </span>
              </div>
            ) : (
              <p className="text-xs text-text-muted">
                {isConnected ? "VPN tunnel is active" : "Enter your password to connect"}
              </p>
            )}
          </div>
        </div>

        {!isConnected && (
          <div className="mb-5 w-full">
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-text-muted">
              Connection Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleConnect()}
                placeholder="Enter your password"
                autoFocus
                className="w-full rounded-lg border border-border bg-surface px-4 py-3 pr-11 text-sm text-text-main placeholder-text-muted outline-none transition-colors focus:border-primary/60"
              />
              <button
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-main"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="mb-4 w-full rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
            {error}
          </div>
        )}

        {isConnected ? (
          <button
            onClick={handleDisconnect}
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm font-semibold text-danger transition-colors hover:bg-danger/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Disconnecting...
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4" />
                Disconnect
              </>
            )}
          </button>
        ) : (
          <button
            onClick={handleConnect}
            disabled={loading || !password}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Connecting...
              </>
            ) : (
              <>
                <Wifi className="h-4 w-4" />
                Connect
              </>
            )}
          </button>
        )}
      </div>

      {showDeleteConfirm && (
        <div className="absolute inset-0 flex items-center justify-center bg-bg/90 backdrop-blur-sm">
          <div className="mx-6 rounded-xl border border-border bg-surface p-6 shadow-xl">
            <h2 className="mb-2 text-base font-semibold text-text-main">Delete Connection?</h2>
            <p className="mb-5 text-sm text-text-muted">
              This will permanently remove the stored VPN configuration. You will need to import it again.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="flex-1 rounded-lg border border-border px-4 py-2.5 text-sm font-medium text-text-main transition-colors hover:bg-border/30"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="flex-1 rounded-lg bg-danger px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-danger-hover"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {showUninstallConfirm && (
        <div className="absolute inset-0 flex items-center justify-center bg-bg/90 backdrop-blur-sm">
          <div className="mx-6 rounded-xl border border-border bg-surface p-6 shadow-xl">
            <h2 className="mb-2 text-base font-semibold text-text-main">Uninstall Helper?</h2>
            <p className="mb-5 text-sm text-text-muted">
              This removes the privileged helper daemon. You will need to reinstall it (requires admin) before connecting again.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowUninstallConfirm(false)}
                className="flex-1 rounded-lg border border-border px-4 py-2.5 text-sm font-medium text-text-main transition-colors hover:bg-border/30"
              >
                Cancel
              </button>
              <button
                onClick={handleUninstallHelper}
                className="flex-1 rounded-lg bg-danger px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-danger-hover"
              >
                Uninstall
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
