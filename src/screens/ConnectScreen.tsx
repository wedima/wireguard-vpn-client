import { useState, useEffect, useMemo, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Eye, EyeOff, Loader2, Settings2, Wifi, WifiOff,
  Trash2, Wrench, LogOut, Check, RefreshCw,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import wedimaLogo from "../assets/wedima-logo.svg";
import LanguageSwitcher from "../components/LanguageSwitcher";
import { ThemeToggle } from "../components/ThemeToggle";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Card, CardContent } from "../components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuDestructiveItem,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "../components/ui/dialog";

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

interface TrafficPoint {
  timestamp: number;
  txRate: number;
  rxRate: number;
  bytesTx: number;
  bytesRx: number;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

export default function ConnectScreen({ isConnected, connectionName, onStatusChange, onReset }: Props) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autoUpdate, setAutoUpdate] = useState(false);
  const [updateNotice, setUpdateNotice] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showUninstallConfirm, setShowUninstallConfirm] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<TrafficPoint[]>([]);
  const [hoveredPointIndex, setHoveredPointIndex] = useState<number | null>(null);
  const previousSampleRef = useRef<{ bytesTx: number; bytesRx: number; timestamp: number } | null>(null);
  const chartRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    invoke<boolean>("get_auto_update").then(setAutoUpdate).catch(() => {});
    invoke<{ status: string; version: string | null; message: string } | null>("get_update_status")
      .then((report) => {
        if (report?.message && report.status !== "error") setUpdateNotice(report.message);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!isConnected) {
      setStats(null);
      setTrafficHistory([]);
      setHoveredPointIndex(null);
      previousSampleRef.current = null;
      return;
    }
    const poll = async () => {
      try {
        const s = await invoke<Stats>("get_stats");
        const now = Date.now();

        // Read and write the ref OUTSIDE setState — React (StrictMode) calls
        // state-updater callbacks twice to detect side effects, which would
        // zero-out every delta if the ref were mutated inside setState.
        const prev = previousSampleRef.current;
        const elapsedSeconds = prev ? Math.max((now - prev.timestamp) / 1000, 0.5) : 1;
        const txRate = prev ? Math.max((s.bytes_tx - prev.bytesTx) / elapsedSeconds, 0) : 0;
        const rxRate = prev ? Math.max((s.bytes_rx - prev.bytesRx) / elapsedSeconds, 0) : 0;
        previousSampleRef.current = { bytesTx: s.bytes_tx, bytesRx: s.bytes_rx, timestamp: now };

        setStats(s);
        setTrafficHistory((history) => {
          const nextPoint: TrafficPoint = {
            timestamp: now,
            txRate,
            rxRate,
            bytesTx: s.bytes_tx,
            bytesRx: s.bytes_rx,
          };
          return [...history, nextPoint].slice(-40);
        });
      } catch (e) {
        console.error("[get_stats]", e);
      }
    };
    poll();
    const id = setInterval(poll, 700);
    return () => clearInterval(id);
  }, [isConnected]);

  const averagedRate = useMemo(() => {
    if (trafficHistory.length === 0) {
      return { txRate: 0, rxRate: 0 };
    }

    const sampleWindow = trafficHistory.slice(-6);
    const txRate = sampleWindow.reduce((sum, point) => sum + point.txRate, 0) / sampleWindow.length;
    const rxRate = sampleWindow.reduce((sum, point) => sum + point.rxRate, 0) / sampleWindow.length;
    return { txRate, rxRate };
  }, [trafficHistory]);

  const activePoint = useMemo(() => {
    if (trafficHistory.length === 0) return null;
    if (hoveredPointIndex === null) return trafficHistory[trafficHistory.length - 1];
    return trafficHistory[Math.min(hoveredPointIndex, trafficHistory.length - 1)] ?? null;
  }, [hoveredPointIndex, trafficHistory]);

  const chartGeometry = useMemo(() => {
    if (trafficHistory.length === 0) {
      return {
        txAreaPath: "",
        rxAreaPath: "",
        txLinePath: "",
        rxLinePath: "",
        hoverX: null as number | null,
      };
    }

    const maxRate = Math.max(
      ...trafficHistory.map((point) => Math.max(point.txRate, point.rxRate)),
      1
    );
    const totalPoints = trafficHistory.length;
    const xAt = (index: number) => (totalPoints <= 1 ? 0 : (index / (totalPoints - 1)) * 100);
    // Render 0-rate at y=96 (4 % above SVG bottom) so the baseline is always
    // visible as a thin coloured strip even during idle periods.
    const yAt = (value: number) => 96 - (value / maxRate) * 88;

    const txPoints = trafficHistory.map((point, index) => `${xAt(index)},${yAt(point.txRate)}`);
    const rxPoints = trafficHistory.map((point, index) => `${xAt(index)},${yAt(point.rxRate)}`);

    const txAreaPath = `M 0,100 ${txPoints.join(" ")} L 100,100 Z`;
    const rxAreaPath = `M 0,100 ${rxPoints.join(" ")} L 100,100 Z`;
    const txLinePath = txPoints.length > 0 ? `M ${txPoints.join(" L ")}` : "";
    const rxLinePath = rxPoints.length > 0 ? `M ${rxPoints.join(" L ")}` : "";
    const hoverX = hoveredPointIndex === null ? null : xAt(hoveredPointIndex);

    return { txAreaPath, rxAreaPath, txLinePath, rxLinePath, hoverX };
  }, [hoveredPointIndex, trafficHistory]);

  const setHoverFromClientX = (clientX: number) => {
    if (!chartRef.current || trafficHistory.length === 0) return;
    const rect = chartRef.current.getBoundingClientRect();
    if (rect.width <= 0) return;
    const ratio = Math.min(Math.max((clientX - rect.left) / rect.width, 0), 1);
    const pointIndex = Math.round(ratio * (trafficHistory.length - 1));
    setHoveredPointIndex(pointIndex);
  };

  const handleConnect = async () => {
    if (!password) return setError(t("connect.errors.missingPassword"));
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

  const handleToggleAutoUpdate = async () => {
    const next = !autoUpdate;
    setAutoUpdate(next);
    setError(null);
    try {
      await invoke("set_auto_update", { enabled: next });
      if (next) {
        const report = await invoke<{ message: string }>("check_for_update");
        setUpdateNotice(report.message);
      } else {
        setUpdateNotice(null);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handleCheckUpdates = async () => {
    setLoading(true);
    setError(null);
    try {
      const report = await invoke<{ message: string }>("check_for_update");
      setUpdateNotice(report.message);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
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
    <div className="flex h-screen flex-col bg-background">
      <header className="flex items-center justify-between border-b px-4 py-3">
        <div className="flex flex-col justify-center">
          <img src={wedimaLogo} alt={t("common.appName")} className="h-5 brightness-0 dark:invert" />
          {connectionName && (
            <span className="mt-0.5 text-xs text-muted-foreground">{connectionName}</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <ThemeToggle />
          <LanguageSwitcher />
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" title={t("common.settings")}>
                <Settings2 className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={handleToggleAutoUpdate}>
                <Check className={`h-4 w-4 shrink-0 ${autoUpdate ? "opacity-100" : "opacity-0"}`} />
                {t("connect.autoUpdate")}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleCheckUpdates}>
                <RefreshCw className="h-4 w-4 shrink-0" />
                {t("connect.checkForUpdates")}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuDestructiveItem onClick={() => setShowDeleteConfirm(true)}>
                <Trash2 className="h-4 w-4 shrink-0" />
                {t("connect.deleteConnection")}
              </DropdownMenuDestructiveItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setShowUninstallConfirm(true)}>
                <Wrench className="h-4 w-4 shrink-0" />
                {t("connect.uninstallHelper")}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => invoke("quit_app")}>
                <LogOut className="h-4 w-4 shrink-0" />
                {t("connect.quitApplication")}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <main className="flex flex-1 flex-col items-center justify-center px-6">
        <div className="w-full max-w-md">
          <div className="mb-8 flex flex-col items-center gap-3">
            <div className="text-center">
              <div
                className={`mb-1 flex items-center justify-center gap-1.5 text-sm font-semibold ${
                  isConnected ? "text-primary" : "text-muted-foreground"
                }`}
              >
                <span
                  className={`inline-block h-1.5 w-1.5 rounded-full ${
                    isConnected ? "bg-primary" : "bg-muted-foreground"
                  }`}
                />
                {isConnected ? t("connect.connected") : t("connect.disconnected")}
              </div>
              {!isConnected && (
                <p className="text-xs text-muted-foreground">
                  {t("connect.enterPasswordToConnect")}
                </p>
              )}
            </div>

            {isConnected && (
              <Card className="mt-2 w-full overflow-hidden border-primary/20 bg-card/80">
                <CardContent className="p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <span className="text-xs font-medium text-muted-foreground">{t("connect.liveTraffic")}</span>
                    <div className="flex items-center gap-4 text-[11px]">
                      <span className="flex items-center gap-1.5 text-emerald-500">
                        <span className="h-2 w-2 rounded-full bg-emerald-500" />
                        {t("connect.uploadRate")}: {formatRate(hoveredPointIndex === null ? averagedRate.txRate : (activePoint?.txRate ?? 0))}
                      </span>
                      <span className="flex items-center gap-1.5 text-sky-400">
                        <span className="h-2 w-2 rounded-full bg-sky-400" />
                        {t("connect.downloadRate")}: {formatRate(hoveredPointIndex === null ? averagedRate.rxRate : (activePoint?.rxRate ?? 0))}
                      </span>
                    </div>
                  </div>

                  <div className="rounded-lg border border-border/70 bg-background/40 p-2">
                    <svg
                      ref={chartRef}
                      viewBox="0 0 100 100"
                      preserveAspectRatio="none"
                      className="h-40 w-full"
                      onPointerMove={(event) => setHoverFromClientX(event.clientX)}
                      onPointerEnter={(event) => setHoverFromClientX(event.clientX)}
                      onPointerLeave={() => setHoveredPointIndex(null)}
                    >
                      <defs>
                        <linearGradient id="upload-area" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#10b981" stopOpacity="0.38" />
                          <stop offset="100%" stopColor="#10b981" stopOpacity="0.03" />
                        </linearGradient>
                        <linearGradient id="download-area" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.34" />
                          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.03" />
                        </linearGradient>
                      </defs>

                      {[20, 40, 60, 80].map((gridY) => (
                        <line
                          key={gridY}
                          x1="0"
                          x2="100"
                          y1={gridY}
                          y2={gridY}
                          stroke="hsl(var(--border))"
                          strokeOpacity="0.3"
                          strokeWidth="0.45"
                        />
                      ))}

                      {chartGeometry.rxAreaPath && (
                        <path d={chartGeometry.rxAreaPath} fill="url(#download-area)" />
                      )}
                      {chartGeometry.txAreaPath && (
                        <path d={chartGeometry.txAreaPath} fill="url(#upload-area)" />
                      )}

                      {chartGeometry.rxLinePath && (
                        <path
                          d={chartGeometry.rxLinePath}
                          fill="none"
                          stroke="#38bdf8"
                          strokeWidth="1.2"
                          vectorEffect="non-scaling-stroke"
                        />
                      )}
                      {chartGeometry.txLinePath && (
                        <path
                          d={chartGeometry.txLinePath}
                          fill="none"
                          stroke="#10b981"
                          strokeWidth="1.2"
                          vectorEffect="non-scaling-stroke"
                        />
                      )}

                      {chartGeometry.hoverX !== null && (
                        <line
                          x1={chartGeometry.hoverX}
                          x2={chartGeometry.hoverX}
                          y1="0"
                          y2="100"
                          stroke="hsl(var(--foreground))"
                          strokeOpacity="0.35"
                          strokeDasharray="2 2"
                          strokeWidth="0.7"
                        />
                      )}
                    </svg>
                  </div>

                  <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded-md border border-border/70 bg-background/30 px-3 py-2">
                      <div className="mb-1 flex items-center gap-2 text-muted-foreground">
                        <span className="h-2 w-2 rounded-full bg-emerald-500" />
                        {t("connect.totalUpload")}
                      </div>
                      <div className="font-semibold text-emerald-500">
                        {formatBytes(activePoint?.bytesTx ?? stats?.bytes_tx ?? 0)}
                      </div>
                    </div>
                    <div className="rounded-md border border-border/70 bg-background/30 px-3 py-2">
                      <div className="mb-1 flex items-center gap-2 text-muted-foreground">
                        <span className="h-2 w-2 rounded-full bg-sky-400" />
                        {t("connect.totalDownload")}
                      </div>
                      <div className="font-semibold text-sky-400">
                        {formatBytes(activePoint?.bytesRx ?? stats?.bytes_rx ?? 0)}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {!isConnected && (
              <div
                className="relative flex h-20 w-20 items-center justify-center rounded-full border-2 border-border bg-card"
              >
                <WifiOff className="h-9 w-9 text-muted-foreground" />
              </div>
            )}
          </div>

          {!isConnected && (
            <div className="mb-4 space-y-1.5">
              <Label htmlFor="password">{t("connect.connectionPassword")}</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleConnect()}
                  placeholder={t("connect.passwordPlaceholder")}
                  autoFocus
                  className="pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-0 top-0 h-full w-10 rounded-l-none text-muted-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>
          )}

          {updateNotice && !error && (
            <Alert variant="info" className="mb-4">
              <AlertDescription>{updateNotice}</AlertDescription>
            </Alert>
          )}

          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {isConnected ? (
            <Button
              variant="destructive"
              className="w-full"
              onClick={handleDisconnect}
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 className="animate-spin" />
                  {t("connect.disconnecting")}
                </>
              ) : (
                <>
                  <WifiOff />
                  {t("connect.disconnect")}
                </>
              )}
            </Button>
          ) : (
            <Button
              className="w-full"
              onClick={handleConnect}
              disabled={loading || !password}
            >
              {loading ? (
                <>
                  <Loader2 className="animate-spin" />
                  {t("connect.connecting")}
                </>
              ) : (
                <>
                  <Wifi />
                  {t("connect.connect")}
                </>
              )}
            </Button>
          )}
        </div>
      </main>

      <Dialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("connect.deleteTitle")}</DialogTitle>
            <DialogDescription>{t("connect.deleteDescription")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" className="flex-1" onClick={() => setShowDeleteConfirm(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" className="flex-1" onClick={handleDelete}>
              {t("common.delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showUninstallConfirm} onOpenChange={setShowUninstallConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("connect.uninstallTitle")}</DialogTitle>
            <DialogDescription>{t("connect.uninstallDescription")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" className="flex-1" onClick={() => setShowUninstallConfirm(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" className="flex-1" onClick={handleUninstallHelper}>
              {t("connect.uninstall")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
