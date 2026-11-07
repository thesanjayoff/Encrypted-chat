import { useCallback, useEffect, useState } from "react";

type Theme = "light" | "dark" | "system";
const STORAGE_KEY = "e2e-chat-theme";

function apply(theme: Theme): void {
  const isDark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", isDark);
}

export function useTheme(): { theme: Theme; setTheme: (t: Theme) => void } {
  const [theme, setThemeState] = useState<Theme>(() => {
    try {
      return (localStorage.getItem(STORAGE_KEY) as Theme) || "system";
    } catch {
      return "system";
    }
  });

  useEffect(() => {
    apply(theme);
  }, [theme]);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      /* best effort; theme just won't persist across reloads */
    }
  }, []);

  return { theme, setTheme };
}
