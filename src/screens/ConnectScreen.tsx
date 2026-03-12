import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Eye, EyeOff, Loader2, Settings2, Wifi, WifiOff,
  Trash2, Wrench, ArrowUp, ArrowDown, LogOut,
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
import { Separator } from "../components/ui/separator";
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

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export default function ConnectScreen({ isConnected, connectionName, onStatusChange, onReset }: Props) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showUninstallConfirm, setShowUninstallConfirm] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);

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
        <div className="w-full max-w-xs">
          <div className="mb-8 flex flex-col items-center gap-3">
            <div
              className={`relative flex h-20 w-20 items-center justify-center rounded-full border-2 transition-all duration-500 ${
                isConnected
                  ? "border-primary bg-primary/10"
                  : "border-border bg-card"
              }`}
            >
              {isConnected && (
                <span className="absolute inset-0 animate-ping rounded-full bg-primary/20" />
              )}
              {isConnected ? (
                <Wifi className="h-9 w-9 text-primary" />
              ) : (
                <WifiOff className="h-9 w-9 text-muted-foreground" />
              )}
            </div>

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
              {isConnected && stats ? (
                <Card className="mt-2">
                  <CardContent className="flex items-center gap-6 px-5 py-3">
                    <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <ArrowUp className="h-3 w-3 text-primary" />
                      {formatBytes(stats.bytes_tx)}
                    </span>
                    <Separator orientation="vertical" className="h-4" />
                    <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <ArrowDown className="h-3 w-3 text-primary" />
                      {formatBytes(stats.bytes_rx)}
                    </span>
                  </CardContent>
                </Card>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {isConnected ? t("connect.tunnelActive") : t("connect.enterPasswordToConnect")}
                </p>
              )}
            </div>
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
