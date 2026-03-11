import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Eye, EyeOff, Loader2, KeyRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import wedimaLogo from "../assets/wedima-logo.svg";
import LanguageSwitcher from "../components/LanguageSwitcher";

interface Props {
  onPasswordSet: () => void;
}

export default function SetupPasswordScreen({ onPasswordSet }: Props) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (password.length < 8) {
      return setError(t("setupPassword.errors.minLength"));
    }
    if (password !== confirm) {
      return setError(t("setupPassword.errors.mismatch"));
    }

    setLoading(true);
    setError(null);
    try {
      await invoke("setup_connection_password", { password });
      onPasswordSet();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen flex-col bg-bg">
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <img src={wedimaLogo} alt={t("common.appName")} className="h-6 brightness-0 invert" />
        <LanguageSwitcher />
      </div>

      <div className="flex flex-1 flex-col justify-center px-8">
        <div className="mb-6 flex h-12 w-12 items-center justify-center rounded-xl border border-primary/30 bg-primary/10">
          <KeyRound className="h-6 w-6 text-primary" />
        </div>

        <h1 className="mb-1 text-xl font-semibold text-text-main">{t("setupPassword.title")}</h1>
        <p className="mb-8 text-sm text-text-muted">
          {t("setupPassword.description")}
        </p>

        <div className="mb-4">
          <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-text-muted">
            {t("setupPassword.newPassword")}
          </label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t("setupPassword.newPasswordPlaceholder")}
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

        <div className="mb-6">
          <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-text-muted">
            {t("setupPassword.confirmPassword")}
          </label>
          <input
            type={showPassword ? "text" : "password"}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder={t("setupPassword.confirmPasswordPlaceholder")}
            className="w-full rounded-lg border border-border bg-surface px-4 py-3 text-sm text-text-main placeholder-text-muted outline-none transition-colors focus:border-primary/60"
          />
        </div>

        {password.length > 0 && (
          <div className="mb-4 flex gap-1">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className={`h-1 flex-1 rounded-full transition-colors ${
                  password.length >= (i + 1) * 3
                    ? i < 1
                      ? "bg-danger"
                      : i < 2
                        ? "bg-yellow-500"
                        : i < 3
                          ? "bg-primary/70"
                          : "bg-primary"
                    : "bg-border"
                }`}
              />
            ))}
          </div>
        )}

        {error && (
          <div className="mb-4 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
            {error}
          </div>
        )}

        <button
          onClick={handleSubmit}
          disabled={loading || !password || !confirm}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              {t("setupPassword.settingUp")}
            </>
          ) : (
            t("setupPassword.submit")
          )}
        </button>
      </div>
    </div>
  );
}
