import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
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

interface Props {
  onImported: () => void;
}

type FileType = "encrypted" | "plain" | null;

export default function ImportScreen({ onImported }: Props) {
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
    if (!filePath) return setError("Please select a config file.");
    if (fileType === "encrypted" && !password) return setError("Please enter the decryption password.");

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
    <div className="flex h-screen flex-col bg-bg">
      <div className="flex items-center border-b border-border px-6 py-4">
        <img src={wedimaLogo} alt="Wedima VPN WG" className="h-6 brightness-0 invert" />
      </div>

      <div className="flex flex-1 flex-col justify-center px-8">
        <h1 className="mb-1 text-xl font-semibold text-text-main">Import Configuration</h1>
        <p className="mb-8 text-sm text-text-muted">
          Select your WireGuard config — encrypted or plain. The file type is detected automatically.
        </p>

        <div className="mb-5">
          <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-text-muted">
            WireGuard Config File
          </label>

          {!filePath ? (
            <button
              onClick={handleFilePick}
              className="flex w-full items-center gap-3 rounded-lg border border-dashed border-border bg-surface px-4 py-3 text-sm transition-colors hover:border-primary/50 hover:bg-surface/80"
            >
              <FolderOpen className="h-4 w-4 shrink-0 text-text-muted" />
              <span className="text-text-muted">Select .conf or .enc file...</span>
            </button>
          ) : (
            <div
              className={`flex items-center gap-3 rounded-lg border px-4 py-3 text-sm transition-colors ${
                fileType === "encrypted"
                  ? "border-yellow-600/40 bg-yellow-600/10"
                  : fileType === "plain"
                    ? "border-primary/40 bg-primary/10"
                    : "border-border bg-surface"
              }`}
            >
              {detecting ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-text-muted" />
              ) : fileType === "encrypted" ? (
                <Lock className="h-4 w-4 shrink-0 text-yellow-500" />
              ) : (
                <FileText className="h-4 w-4 shrink-0 text-primary" />
              )}

              <span className="flex-1 truncate text-text-main">{fileName}</span>

              {fileType && (
                <span
                  className={`shrink-0 rounded px-1.5 py-0.5 text-xs font-medium ${
                    fileType === "encrypted"
                      ? "bg-yellow-600/20 text-yellow-400"
                      : "bg-primary/20 text-primary"
                  }`}
                >
                  {fileType === "encrypted" ? "Encrypted" : "Plain"}
                </span>
              )}

              <button
                onClick={handleClearFile}
                className="ml-1 shrink-0 text-text-muted hover:text-text-main"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {fileType === "encrypted" && (
          <div className="mb-6">
            <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-text-muted">
              Decryption Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleImport()}
                placeholder="Enter the password provided by your admin"
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

        {fileType === "plain" && (
          <div className="mb-6 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-text-muted">
            Plain config detected. No decryption needed — you will set a personal connection password in the next step.
          </div>
        )}

        {!fileType && !detecting && !filePath && (
          <div className="mb-6" />
        )}

        {error && (
          <div className="mb-4 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
            {error}
          </div>
        )}

        <button
          onClick={handleImport}
          disabled={loading || !canImport}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Importing...
            </>
          ) : fileType === "encrypted" ? (
            "Decrypt & Import"
          ) : (
            "Import"
          )}
        </button>

        <p className="mt-6 text-center text-xs text-text-muted">
          The config is stored encrypted on your device. You will never see its contents.
        </p>
      </div>
    </div>
  );
}
