"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  type ReactNode,
} from "react";
import { ShieldAlert, Key, LogOut } from "lucide-react";

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------
interface AuthContextValue {
  apiKey: string | null;
  setApiKey: (key: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Access the current auth state from anywhere inside <AuthGate>. */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an <AuthGate>");
  }
  return ctx;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const STORAGE_KEY = "vigilwolf_api_key";

function readStoredKey(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(STORAGE_KEY);
}

function writeStoredKey(key: string): void {
  localStorage.setItem(STORAGE_KEY, key);
}

function removeStoredKey(): void {
  localStorage.removeItem(STORAGE_KEY);
}

// ---------------------------------------------------------------------------
// Login form
// ---------------------------------------------------------------------------
function LoginForm({ onSubmit }: { onSubmit: (key: string) => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) {
      setError("API key is required");
      return;
    }
    setError(null);
    onSubmit(trimmed);
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950">
      <div className="w-full max-w-sm rounded-lg border border-zinc-800 bg-zinc-900 p-8 shadow-xl">
        {/* Brand */}
        <div className="mb-8 flex items-center justify-center gap-2">
          <ShieldAlert className="h-7 w-7 text-red-500" />
          <span className="text-xl font-bold tracking-tight text-zinc-100">
            VigilWolf
          </span>
        </div>

        <h1 className="mb-2 text-center text-lg font-semibold text-zinc-100">
          Enter your API key
        </h1>
        <p className="mb-6 text-center text-sm text-zinc-500">
          An API key is required to access the platform.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="api-key"
              className="mb-1.5 block text-sm font-medium text-zinc-300"
            >
              API Key
            </label>
            <input
              id="api-key"
              type="password"
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                if (error) setError(null);
              }}
              placeholder="vw-..."
              autoFocus
              className="h-10 w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500/50"
            />
            {error && (
              <p className="mt-1.5 text-xs text-red-400">{error}</p>
            )}
          </div>

          <button
            type="submit"
            className="flex h-10 w-full items-center justify-center gap-2 rounded-md bg-red-600 text-sm font-semibold text-white transition-colors hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:ring-offset-2 focus:ring-offset-zinc-900"
          >
            <Key className="h-4 w-4" />
            Connect
          </button>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// AuthGate
// ---------------------------------------------------------------------------
export function AuthGate({ children }: { children: ReactNode }) {
  const [apiKey, setApiKeyState] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  // Read from localStorage once on mount (SSR-safe)
  useEffect(() => {
    const stored = readStoredKey();
    if (stored) {
      setApiKeyState(stored);
    }
    setHydrated(true);
  }, []);

  function handleSetApiKey(key: string) {
    writeStoredKey(key);
    setApiKeyState(key);
  }

  function handleLogout() {
    removeStoredKey();
    setApiKeyState(null);
  }

  // Prevent hydration mismatch — render nothing until client-side state is ready
  if (!hydrated) {
    return null;
  }

  // No key — show login form
  if (!apiKey) {
    return <LoginForm onSubmit={handleSetApiKey} />;
  }

  // Authenticated — provide context and render children
  return (
    <AuthContext.Provider
      value={{ apiKey, setApiKey: handleSetApiKey, logout: handleLogout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Logout button (optional convenience)
// ---------------------------------------------------------------------------
export function LogoutButton() {
  const { logout } = useAuth();
  return (
    <button
      onClick={logout}
      className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
      title="Disconnect API key"
    >
      <LogOut className="h-3.5 w-3.5" />
      Disconnect
    </button>
  );
}