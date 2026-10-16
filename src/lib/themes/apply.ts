import { useEffect } from "react";

import { useUiStore } from "@/stores/uiStore";

import { DEFAULT_THEME_ID, getTheme } from "./themes";
import type { Theme } from "./types";

/**
 * Write a Theme's CSS-var map onto `document.documentElement` so it
 * overrides the static `:root` / `.dark` blocks in index.css.
 *
 * Why direct style.setProperty instead of swapping a class name:
 * the static stylesheet defines hardcoded values for both light
 * (`:root`) and dark (`.dark`) modes. Class-swapping would require
 * 11 CSS classes plus careful specificity rules. Setting variables
 * directly on the root element wins via inline-style specificity
 * regardless of what the static stylesheet says, with no class
 * machinery.
 *
 * The `dark` class on `<html>` (set statically in index.html) stays.
 * It tells Tailwind's `dark:` variants to resolve — which themes
 * benefit from since the existing chat / sidebar / dialog code
 * uses `dark:` utilities throughout. For light themes (GitHub
 * Light, Catppuccin Latte), we flip the `dark` class OFF so those
 * `dark:` rules don't apply.
 */
export function applyTheme(theme: Theme): void {
  if (typeof document === "undefined") return; // SSR / test guard

  const root = document.documentElement;
  for (const [name, value] of Object.entries(theme.chrome)) {
    root.style.setProperty(`--${name}`, value);
  }
  if (theme.mode === "dark") {
    root.classList.add("dark");
  } else {
    root.classList.remove("dark");
  }
  root.dataset.themeId = theme.id;
}

/**
 * Mount-once hook that applies the active theme on first render and
 * any time the user picks a different one. Call from App root.
 */
export function useApplyTheme(): void {
  const themeId = useUiStore((s) => s.preferences.themeId);

  useEffect(() => {
    applyTheme(getTheme(themeId ?? DEFAULT_THEME_ID));
  }, [themeId]);
}
