import { useRef } from "react";

import { Ban, Check, Palette } from "lucide-react";

import {
  DEVICE_COLORS,
  DEVICE_COLOR_LABELS,
  deviceColorVar,
  hexIsLight,
  isAccentHex,
} from "@/lib/deviceColors";
import { cn } from "@/lib/utils";

export interface DeviceColorPickerProps {
  /** Empty string = no color; otherwise a palette token or `#rrggbb`. */
  value: string;
  onChange: (value: string) => void;
}

const SWATCH =
  "flex h-6 w-6 items-center justify-center rounded-full transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background";
const SELECTED = "ring-2 ring-ring ring-offset-1 ring-offset-background";

/** Starting point for the native picker when no custom hex is active yet
 *  (a mid-blue — arbitrary, but `<input type="color">` requires a valid
 *  value at all times). */
const CUSTOM_DEFAULT_HEX = "#3b82f6";

/**
 * Swatch row for a device's accent color. Renders a "None" option, one
 * button per curated palette token, and (v6.3.0) a Custom swatch backed by
 * the native color picker. Curated tokens stay theme-aware (light/dark
 * variants in index.css); a custom hex is one value in both modes — the
 * user's trade-off to make. The native `<input type="color">` only ever
 * emits strict `#rrggbb`, so this control constrains input by construction
 * (the storage predicate `isAccentValue` re-checks anyway).
 */
export function DeviceColorPicker({ value, onChange }: DeviceColorPickerProps) {
  const customInputRef = useRef<HTMLInputElement | null>(null);
  const customActive = isAccentHex(value);
  // One normalized spelling everywhere (swatch, tooltip, readout, input
  // value) — mixed-case renders looked like two different colors.
  const hex = customActive ? value.toLowerCase() : CUSTOM_DEFAULT_HEX;

  return (
    <div role="radiogroup" aria-label="Accent color" className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        role="radio"
        aria-checked={value === ""}
        aria-label="No color"
        title="None"
        onClick={() => onChange("")}
        className={cn(
          SWATCH,
          "border border-border text-muted-foreground",
          value === "" && SELECTED,
        )}
      >
        <Ban className="h-3.5 w-3.5" />
      </button>
      {DEVICE_COLORS.map((token) => {
        const selected = value === token;
        return (
          <button
            key={token}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={DEVICE_COLOR_LABELS[token]}
            title={DEVICE_COLOR_LABELS[token]}
            onClick={() => onChange(token)}
            className={cn(SWATCH, "border border-black/10", selected && SELECTED)}
            style={{ backgroundColor: deviceColorVar(token) }}
          >
            {selected && (
              <Check className="h-3.5 w-3.5 text-white drop-shadow-[0_1px_1px_rgba(0,0,0,0.55)]" />
            )}
          </button>
        );
      })}
      <button
        type="button"
        role="radio"
        aria-checked={customActive}
        aria-label="Custom color"
        title={customActive ? `Custom (${hex}) — doesn't adapt to light/dark` : "Custom color…"}
        onClick={() => {
          // Commit the default IMMEDIATELY on activation. `<input
          // type="color">` fires no change event when the user confirms
          // its pre-set value, so without this, picking exactly the
          // default blue silently dropped the selection — and the
          // default is the single likeliest pick, since it's what the
          // native dialog opens showing. Cancelling after this leaves
          // the default selected, which is visible and one click to
          // undo — strictly better than an invisible no-op.
          if (!customActive) onChange(CUSTOM_DEFAULT_HEX);
          customInputRef.current?.click();
        }}
        className={cn(
          SWATCH,
          "border",
          customActive ? "border-black/10" : "border-dashed border-border text-muted-foreground",
          customActive && SELECTED,
        )}
        style={customActive ? { backgroundColor: hex } : undefined}
      >
        {customActive ? (
          <Check
            className={cn(
              "h-3.5 w-3.5",
              hexIsLight(value)
                ? "text-black/80"
                : "text-white drop-shadow-[0_1px_1px_rgba(0,0,0,0.55)]",
            )}
          />
        ) : (
          <Palette className="h-3.5 w-3.5" />
        )}
      </button>
      {/* The real input stays visually hidden; the swatch button proxies a
          click into it so the native picker opens. `type="color"` can only
          ever emit a strict #rrggbb — never partial or hostile input. */}
      <input
        ref={customInputRef}
        type="color"
        value={hex}
        onChange={(e) => onChange(e.target.value.toLowerCase())}
        className="sr-only"
        tabIndex={-1}
        aria-hidden="true"
        data-testid="device-color-custom-input"
      />
      {customActive && <span className="font-mono text-xs text-muted-foreground">{hex}</span>}
    </div>
  );
}
