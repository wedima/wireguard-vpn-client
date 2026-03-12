import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Eye, EyeOff, Loader2, KeyRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import wedimaLogo from "../assets/wedima-logo.svg";
import LanguageSwitcher from "../components/LanguageSwitcher";
import { ThemeToggle } from "../components/ThemeToggle";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Label } from "../components/ui/label";
import { Alert, AlertDescription } from "../components/ui/alert";
import { cn } from "../lib/utils";

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

  const strengthSegments = [0, 1, 2, 3].map((i) => {
    const filled = password.length >= (i + 1) * 3;
    return filled
      ? i < 1 ? "bg-destructive"
      : i < 2 ? "bg-warning"
      : i < 3 ? "bg-primary/70"
      : "bg-primary"
      : "bg-border";
  });

  return (
    <div className="flex h-screen flex-col bg-background">
      <header className="flex items-center justify-between border-b px-4 py-3">
        <img src={wedimaLogo} alt={t("common.appName")} className="h-5 brightness-0 dark:invert" />
        <div className="flex items-center gap-1">
          <LanguageSwitcher />
          <ThemeToggle />
        </div>
      </header>

      <main className="flex flex-1 flex-col justify-center px-6">
        <div className="w-full max-w-xs mx-auto">
          <div className="mb-5 flex h-10 w-10 items-center justify-center rounded-lg border bg-card">
            <KeyRound className="h-5 w-5 text-primary" />
          </div>

          <h1 className="mb-1 text-lg font-semibold tracking-tight">{t("setupPassword.title")}</h1>
          <p className="mb-6 text-sm text-muted-foreground">
            {t("setupPassword.description")}
          </p>

          <div className="mb-3 space-y-1.5">
            <Label htmlFor="new-password">{t("setupPassword.newPassword")}</Label>
            <div className="relative">
              <Input
                id="new-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("setupPassword.newPasswordPlaceholder")}
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

          {password.length > 0 && (
            <div className="mb-3 flex gap-1">
              {strengthSegments.map((colorClass, i) => (
                <div
                  key={i}
                  className={cn("h-1 flex-1 rounded-full transition-colors", colorClass)}
                />
              ))}
            </div>
          )}

          <div className="mb-5 space-y-1.5">
            <Label htmlFor="confirm-password">{t("setupPassword.confirmPassword")}</Label>
            <Input
              id="confirm-password"
              type={showPassword ? "text" : "password"}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              placeholder={t("setupPassword.confirmPasswordPlaceholder")}
            />
          </div>

          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Button
            onClick={handleSubmit}
            disabled={loading || !password || !confirm}
            className="w-full"
          >
            {loading ? (
              <>
                <Loader2 className="animate-spin" />
                {t("setupPassword.settingUp")}
              </>
            ) : (
              t("setupPassword.submit")
            )}
          </Button>
        </div>
      </main>
    </div>
  );
}
