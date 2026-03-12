import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { useTranslation } from "react-i18next";
import {
  FolderOpen,
  Eye,
  EyeOff,
  Loader2,
  Lock,
  FileText,
  X,
} from "lucide-react";
import wedimaLogo from "../assets/wedima-logo.svg";
import LanguageSwitcher from "../components/LanguageSwitcher";
import { ThemeToggle } from "../components/ThemeToggle";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Badge } from "../components/ui/badge";

interface Props {
  onImported: () => void;
}

type FileType = "encrypted" | "plain" | null;

export default function ImportScreen({ onImported }: Props) {
  const { t } = useTranslation();
  const [filePath, setFilePath] = useState<string | null>(null);
  const [fileType, setFileType] = useState<FileType>(null);
  const [detecting, setDetecting] = useState(false);
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFilePick = async () => {
    const selected = await open({
      multiple: false,
      filters: [
        { name: "WireGuard Config", extensions: ["conf", "enc", "wgenc"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });
    if (!selected || typeof selected !== "string") return;

    setFilePath(selected);
    setFileType(null);
    setPassword("");
    setError(null);
    setDetecting(true);

    try {
      const type = await invoke<string>("detect_config_type", { filePath: selected });
      setFileType(type as FileType);
    } catch (e) {
      setError(String(e));
      setFilePath(null);
    } finally {
      setDetecting(false);
    }
  };

  const handleClearFile = () => {
    setFilePath(null);
    setFileType(null);
    setPassword("");
    setError(null);
  };

  const handleImport = async () => {
    if (!filePath) return setError(t("import.errors.selectFile"));
    if (fileType === "encrypted" && !password) return setError(t("import.errors.enterDecryptionPassword"));

    setLoading(true);
    setError(null);
    try {
      await invoke("import_config", {
        filePath,
        password: fileType === "encrypted" ? password : null,
      });
      onImported();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const fileName = filePath ? filePath.split(/[/\\]/).pop() : null;
  const canImport = !!filePath && !!fileType && (fileType === "plain" || !!password);

  return (
    <div className="flex h-screen flex-col bg-background">
      <header className="flex items-center justify-between border-b px-4 py-3">
        <img src={wedimaLogo} alt={t("common.appName")} className="h-5 brightness-0 dark:invert" />
        <div className="flex items-center gap-1">
          <ThemeToggle />
          <LanguageSwitcher />
        </div>
      </header>

      <main className="flex flex-1 flex-col justify-center px-6">
        <div className="w-full max-w-xs mx-auto">
          <h1 className="mb-1 text-lg font-semibold tracking-tight">{t("import.title")}</h1>
          <p className="mb-6 text-sm text-muted-foreground">
            {t("import.description")}
          </p>

          <div className="mb-4 space-y-1.5">
            <Label>{t("import.configFileLabel")}</Label>

            {!filePath ? (
              <button
                onClick={handleFilePick}
                className="flex w-full items-center gap-3 rounded-md border border-dashed bg-card px-4 py-3 text-sm text-muted-foreground transition-colors hover:border-primary/60 hover:bg-accent hover:text-foreground"
              >
                <FolderOpen className="h-4 w-4 shrink-0" />
                {t("import.selectFile")}
              </button>
            ) : (
              <div
                className={`flex items-center gap-3 rounded-md border px-4 py-3 text-sm transition-colors ${
                  fileType === "encrypted"
                    ? "border-warning/40 bg-warning/5"
                    : fileType === "plain"
                      ? "border-primary/40 bg-primary/5"
                      : "border-border bg-card"
                }`}
              >
                {detecting ? (
                  <Loader2 className="h-4 w-4 shrink-0 animate-spin text-muted-foreground" />
                ) : fileType === "encrypted" ? (
                  <Lock className="h-4 w-4 shrink-0 text-warning" />
                ) : (
                  <FileText className="h-4 w-4 shrink-0 text-primary" />
                )}

                <span className="flex-1 truncate font-medium">{fileName}</span>

                {fileType && (
                  <Badge variant={fileType === "encrypted" ? "warning" : "default"}>
                    {fileType === "encrypted" ? t("import.encrypted") : t("import.plain")}
                  </Badge>
                )}

                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={handleClearFile}
                  className="ml-1 h-6 w-6 shrink-0 text-muted-foreground"
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
            )}
          </div>

          {fileType === "encrypted" && (
            <div className="mb-4 space-y-1.5">
              <Label htmlFor="decrypt-password">{t("import.decryptionPassword")}</Label>
              <div className="relative">
                <Input
                  id="decrypt-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleImport()}
                  placeholder={t("import.decryptionPlaceholder")}
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

          {fileType === "plain" && (
            <Alert variant="info" className="mb-4">
              <AlertDescription>{t("import.plainInfo")}</AlertDescription>
            </Alert>
          )}

          {!fileType && !detecting && !filePath && <div className="mb-4" />}

          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Button onClick={handleImport} disabled={loading || !canImport} className="w-full">
            {loading ? (
              <>
                <Loader2 className="animate-spin" />
                {t("import.importing")}
              </>
            ) : fileType === "encrypted" ? (
              t("import.decryptAndImport")
            ) : (
              t("import.import")
            )}
          </Button>

          <p className="mt-5 text-center text-xs text-muted-foreground">
            {t("import.footer")}
          </p>
        </div>
      </main>
    </div>
  );
}
