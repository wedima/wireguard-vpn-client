import { useTranslation } from "react-i18next";

export default function LanguageSwitcher() {
  const { i18n, t } = useTranslation();

  const currentLanguage = i18n.resolvedLanguage?.startsWith("de") ? "de" : "en";

  return (
    <label className="flex items-center gap-2 text-xs text-text-muted" aria-label={t("languageSwitcher.label")}>
      <span className="sr-only">{t("languageSwitcher.label")}</span>
      <select
        value={currentLanguage}
        onChange={(e) => {
          void i18n.changeLanguage(e.target.value);
        }}
        className="rounded-md border border-border bg-surface px-2 py-1 text-xs text-text-main outline-none transition-colors focus:border-primary/60"
      >
        <option value="en">{t("languageSwitcher.english")}</option>
        <option value="de">{t("languageSwitcher.german")}</option>
      </select>
    </label>
  );
}
