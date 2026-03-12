import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Loader2 } from "lucide-react";
import ImportScreen from "./screens/ImportScreen";
import SetupPasswordScreen from "./screens/SetupPasswordScreen";
import ConnectScreen from "./screens/ConnectScreen";
import { ThemeProvider } from "./components/ThemeProvider";

export interface StatusResult {
  has_config: boolean;
  has_password: boolean;
  is_connected: boolean;
  connection_name: string | null;
}

type Screen = "loading" | "import" | "setup-password" | "connect";

function AppContent() {
  const [screen, setScreen] = useState<Screen>("loading");
  const [isConnected, setIsConnected] = useState(false);
  const [connectionName, setConnectionName] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const status = await invoke<StatusResult>("check_status");
      setIsConnected(status.is_connected);
      setConnectionName(status.connection_name ?? null);
      if (!status.has_config) {
        setScreen("import");
      } else if (!status.has_password) {
        setScreen("setup-password");
      } else {
        setScreen("connect");
      }
    } catch {
      setScreen("import");
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  if (screen === "loading") {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (screen === "import") {
    return <ImportScreen onImported={refresh} />;
  }

  if (screen === "setup-password") {
    return <SetupPasswordScreen onPasswordSet={refresh} />;
  }

  return (
    <ConnectScreen
      isConnected={isConnected}
      connectionName={connectionName}
      onStatusChange={refresh}
      onReset={async () => {
        await invoke("reset_config");
        refresh();
      }}
    />
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}
