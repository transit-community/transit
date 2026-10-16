import { useState } from "react";

import { useQuery } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { listAuthProfiles, listDevices, type DeviceInput, type DeviceMeta } from "@/lib/api";
import { loadSelectableMonospaceFonts } from "@/lib/fonts";
import { useBulkUpdateDevices } from "@/lib/mutations";
import { deviceMetaToInput } from "@/lib/netboxSync";
import { queryClient } from "@/lib/queryClient";
import { CUSTOM_VENDOR_PATTERN } from "@/lib/schemas";
import { TERMINAL_FONT_SIZE_MAX, TERMINAL_FONT_SIZE_MIN } from "@/stores/uiStore";

import { DeviceColorPicker } from "./DeviceColorPicker";
import { JumpHostCombobox } from "./JumpHostCombobox";
import { VendorCombobox } from "./VendorCombobox";

/**
 * v6.3.0 bulk device edit (community request): multi-select → right-click →
 * "Edit N devices…". Every row is TRI-STATE — "Leave as is" (the default,
 * so opening + applying is a no-op), a set-value mode, or an off/clear
 * mode. Resolution happens CLIENT-side into complete `DeviceInput`s
 * because the backend `update_device` is a whole-record replace: each
 * entry spreads the device's current fields and carries
 * `allow_weak_crypto` + `netbox_id` through untouched (the same
 * passthrough discipline `EditDeviceDialog`'s tests pin). The backend
 * applies all N in one atomic transaction — a bad row rolls back the
 * whole batch, so this dialog never partially applies.
 *
 * Deliberately NOT covered in bulk: id/host/port (meaningless across N
 * devices) and group/tags (group already has drag + "Move to group").
 * Boolean rows say Leave/On/Off: On writes `true`, Off writes null
 * (removing the TOML key — the wire's off state, matching the single-edit
 * checkbox), and Leave passes the stored value through VERBATIM — an
 * explicit hand-written `= false` survives a bulk edit untouched.
 */

type SetMode = "leave" | "set";
type BoolMode = "leave" | "on" | "off";
/** Rows whose value can be explicitly cleared back to the global default
 *  (terminal font family/size). Clear is its OWN mode — an earlier draft
 *  made "Set with an empty value" mean clear, which turned the freshly
 *  clicked Set mode's default state into a destructive action. */
type ClearableMode = "leave" | "set" | "clear";

export interface BulkEditDevicesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  devices: DeviceMeta[];
}

function ModeButtons<M extends string>({
  value,
  onChange,
  options,
  idBase,
}: {
  value: M;
  onChange: (m: M) => void;
  options: ReadonlyArray<{ value: M; label: string }>;
  idBase: string;
}) {
  return (
    <div role="radiogroup" className="flex shrink-0 gap-1">
      {options.map((o) => (
        <Button
          key={o.value}
          type="button"
          size="sm"
          role="radio"
          aria-checked={value === o.value}
          variant={value === o.value ? "default" : "outline"}
          onClick={() => onChange(o.value)}
          data-testid={`${idBase}-${o.value}`}
        >
          {o.label}
        </Button>
      ))}
    </div>
  );
}

const SET_MODES = [
  { value: "leave", label: "Leave as is" },
  { value: "set", label: "Set" },
] as const;

const BOOL_MODES = [
  { value: "leave", label: "Leave as is" },
  { value: "on", label: "On" },
  { value: "off", label: "Off" },
] as const;

const CLEARABLE_MODES = [
  { value: "leave", label: "Leave as is" },
  { value: "set", label: "Set" },
  { value: "clear", label: "Clear" },
] as const;

/** Row chrome shared by every field (mirrors the Settings row shape). */
function FieldRow({
  label,
  help,
  control,
  value,
}: {
  label: string;
  help?: string;
  control: React.ReactNode;
  value?: React.ReactNode;
}) {
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1 space-y-1">
          <p className="text-sm font-medium">{label}</p>
          {help && <p className="text-xs text-muted-foreground">{help}</p>}
        </div>
        {control}
      </div>
      {value}
    </div>
  );
}

export function BulkEditDevicesDialog({ open, onOpenChange, devices }: BulkEditDevicesDialogProps) {
  const [vendorMode, setVendorMode] = useState<SetMode>("leave");
  const [vendorValue, setVendorValue] = useState("");
  const [authMode, setAuthMode] = useState<SetMode>("leave");
  const [authValue, setAuthValue] = useState("");
  const [colorMode, setColorMode] = useState<SetMode>("leave");
  const [colorValue, setColorValue] = useState("");
  const [boldMode, setBoldMode] = useState<BoolMode>("leave");
  const [syntaxMode, setSyntaxMode] = useState<BoolMode>("leave");
  const [quickMode, setQuickMode] = useState<BoolMode>("leave");
  const [fontFamilyMode, setFontFamilyMode] = useState<ClearableMode>("leave");
  const [fontFamilyValue, setFontFamilyValue] = useState("");
  const [fontSizeMode, setFontSizeMode] = useState<ClearableMode>("leave");
  const [fontSizeValue, setFontSizeValue] = useState(TERMINAL_FONT_SIZE_MIN);
  const [jumpMode, setJumpMode] = useState<ClearableMode>("leave");
  const [jumpValue, setJumpValue] = useState("");

  const authProfiles = useQuery({
    queryKey: ["authProfiles"],
    queryFn: listAuthProfiles,
    enabled: open,
  });
  // Same cache the Settings font picker uses — the datalist keeps a bulk
  // font change from writing a misspelled/autocapitalized family to N
  // devices in one transaction.
  const monospaceFonts = useQuery({
    queryKey: ["monospaceFonts"],
    queryFn: loadSelectableMonospaceFonts,
    enabled: open,
  });
  // v6.5.0 — jump-host targets. Excludes the SELECTION itself (setting a
  // bastion as everyone's jump while bulk-editing the bastion would
  // self-reference and abort the whole batch) and any device whose own
  // chain leads into the selection (would cycle). UX guard only — the
  // backend's atomic revalidate is the enforcement.
  const allDevices = useQuery({
    queryKey: ["devices"],
    queryFn: listDevices,
    enabled: open,
  });
  const selectedIds = new Set(devices.map((d) => d.id));
  const jumpOf = new Map(
    (allDevices.data ?? []).filter((d) => d.jump_via).map((d) => [d.id, d.jump_via]),
  );
  const chainReachesSelection = (startId: string): boolean => {
    const seen = new Set<string>();
    let cursor: string | null | undefined = startId;
    while (cursor && !seen.has(cursor) && seen.size < 8) {
      if (selectedIds.has(cursor)) return true;
      seen.add(cursor);
      cursor = jumpOf.get(cursor);
    }
    return false;
  };
  const jumpTargets = (allDevices.data ?? []).filter(
    (d) => !selectedIds.has(d.id) && !chainReachesSelection(d.id),
  );

  const bulk = useBulkUpdateDevices();

  const vendorInvalid =
    vendorMode === "set" && !CUSTOM_VENDOR_PATTERN.test(vendorValue.trim().toLowerCase());
  const authInvalid = authMode === "set" && authValue.trim() === "";
  // Set REQUIRES a value (Clear is its own mode); the range/int rules are
  // the shared store bounds, and non-integers must be refused here — the
  // wire type is u16, so `12.5` would abort the whole batch at serde.
  const fontFamilyInvalid = fontFamilyMode === "set" && fontFamilyValue.trim() === "";
  const jumpInvalid = jumpMode === "set" && jumpValue.trim() === "";
  const fontSizeInvalid =
    fontSizeMode === "set" &&
    (!Number.isInteger(fontSizeValue) ||
      fontSizeValue < TERMINAL_FONT_SIZE_MIN ||
      fontSizeValue > TERMINAL_FONT_SIZE_MAX);
  const nothingToApply =
    vendorMode === "leave" &&
    authMode === "leave" &&
    colorMode === "leave" &&
    boldMode === "leave" &&
    syntaxMode === "leave" &&
    quickMode === "leave" &&
    fontFamilyMode === "leave" &&
    fontSizeMode === "leave" &&
    jumpMode === "leave";
  const applyDisabled =
    bulk.isPending ||
    nothingToApply ||
    vendorInvalid ||
    authInvalid ||
    fontFamilyInvalid ||
    fontSizeInvalid ||
    jumpInvalid;

  /** Whole-record resolution: the SHARED DeviceMeta→DeviceInput mapper
   *  (the one place a new device field must be added — netbox sync and
   *  this dialog both ride it) with the tri-state patches spread on top.
   *  Everything not patched — `allow_weak_crypto` and `netbox_id`
   *  included — rides through untouched. */
  function resolve(device: DeviceMeta): DeviceInput {
    const patches: Partial<DeviceInput> = {};
    if (vendorMode === "set") patches.vendor = vendorValue.trim().toLowerCase();
    if (authMode === "set") patches.auth = authValue;
    if (colorMode === "set") patches.color = colorValue === "" ? null : colorValue;
    if (boldMode !== "leave") patches.bold_color = boldMode === "on" ? true : null;
    if (syntaxMode !== "leave") patches.syntax_highlighting = syntaxMode === "on" ? true : null;
    if (quickMode !== "leave") patches.quick_copy_paste = quickMode === "on" ? true : null;
    if (fontFamilyMode === "set") patches.font_family = fontFamilyValue.trim();
    if (fontFamilyMode === "clear") patches.font_family = null;
    if (fontSizeMode === "set") patches.font_size = fontSizeValue;
    if (fontSizeMode === "clear") patches.font_size = null;
    // v6.5.0 — jump host. `forward_agent` is deliberately NOT bulk-
    // editable (a security opt-in wants per-device deliberation); it
    // rides through the shared mapper untouched, like allow_weak_crypto.
    if (jumpMode === "set") patches.jump_via = jumpValue;
    if (jumpMode === "clear") patches.jump_via = null;
    return { ...deviceMetaToInput(device), ...patches };
  }

  async function apply() {
    // Resolve against the FRESHEST device records, not the snapshot
    // captured when the menu was clicked — the dialog can sit open while
    // a weak-crypto "remember" or a NetBox sync writes to one of these
    // devices, and a whole-record replace from a stale snapshot would
    // silently revert that. A device deleted mid-dwell stays in the
    // batch and aborts it backend-side (all-or-nothing + honest error).
    const live = queryClient.getQueryData<DeviceMeta[]>(["devices"]);
    const freshest = (d: DeviceMeta) => live?.find((x) => x.id === d.id) ?? d;
    try {
      await bulk.mutateAsync(
        devices.map((d) => {
          const current = freshest(d);
          return { id: current.id, input: resolve(current) };
        }),
      );
      onOpenChange(false);
    } catch {
      // Toast comes from the mutation hook; keep the dialog open so the
      // user's tri-state choices survive a retry.
    }
  }

  const idPreview = devices
    .slice(0, 5)
    .map((d) => d.id)
    .join(", ");
  const idOverflow = devices.length > 5 ? ` +${devices.length - 5} more` : "";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[36rem]">
        <DialogHeader>
          <DialogTitle>Edit {devices.length} devices</DialogTitle>
          <DialogDescription>
            <span className="font-mono text-xs">
              {idPreview}
              {idOverflow}
            </span>
            <br />
            Rows left on “Leave as is” don’t change anything. Changes apply to all selected devices
            in one transaction — if any device fails, nothing is written.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <FieldRow
            label="Vendor"
            help="Assigns the policy pack the agent's command gate uses for these devices."
            control={
              <ModeButtons
                value={vendorMode}
                onChange={setVendorMode}
                options={SET_MODES}
                idBase="bulk-vendor-mode"
              />
            }
            value={
              vendorMode === "set" ? (
                <VendorCombobox value={vendorValue} onChange={setVendorValue} id="bulk-vendor" />
              ) : undefined
            }
          />

          <FieldRow
            label="Auth profile"
            control={
              <ModeButtons
                value={authMode}
                onChange={setAuthMode}
                options={SET_MODES}
                idBase="bulk-auth-mode"
              />
            }
            value={
              authMode === "set" ? (
                <Select onValueChange={setAuthValue} value={authValue}>
                  <SelectTrigger data-testid="bulk-auth-select">
                    <SelectValue placeholder="Pick an auth profile" />
                  </SelectTrigger>
                  <SelectContent>
                    {(authProfiles.data ?? []).map((p) => (
                      <SelectItem key={p.name} value={p.name}>
                        <span className="font-mono">{p.name}</span>
                        <span className="ml-2 text-xs text-muted-foreground">
                          {p.username}@{p.backend}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : undefined
            }
          />

          <FieldRow
            label="Jump host"
            help="Set: tunnel every selected device through one jump host (SSH ProxyJump). Clear: connect them all directly."
            control={
              <ModeButtons
                value={jumpMode}
                onChange={setJumpMode}
                options={CLEARABLE_MODES}
                idBase="bulk-jump-mode"
              />
            }
            value={
              jumpMode === "set" ? (
                <JumpHostCombobox
                  value={jumpValue}
                  onChange={setJumpValue}
                  options={jumpTargets.map((d) => ({ id: d.id, host: d.host, port: d.port }))}
                  emptyText="No eligible devices — a jump host can't be in this selection."
                  data-testid="bulk-jump-select"
                />
              ) : undefined
            }
          />

          <FieldRow
            label="Accent color"
            help="Set mode: pick a palette color, a custom color, or None to clear."
            control={
              <ModeButtons
                value={colorMode}
                onChange={setColorMode}
                options={SET_MODES}
                idBase="bulk-color-mode"
              />
            }
            value={
              colorMode === "set" ? (
                <DeviceColorPicker value={colorValue} onChange={setColorValue} />
              ) : undefined
            }
          />

          <FieldRow
            label="Bold accent"
            help="Renders the accent as a louder background tint on the tab."
            control={
              <ModeButtons
                value={boldMode}
                onChange={setBoldMode}
                options={BOOL_MODES}
                idBase="bulk-bold-mode"
              />
            }
          />

          <FieldRow
            label="Syntax highlighting"
            control={
              <ModeButtons
                value={syntaxMode}
                onChange={setSyntaxMode}
                options={BOOL_MODES}
                idBase="bulk-syntax-mode"
              />
            }
          />

          <FieldRow
            label="Quick copy/paste"
            help="SecureCRT-style: selection auto-copies; right/middle click pastes."
            control={
              <ModeButtons
                value={quickMode}
                onChange={setQuickMode}
                options={BOOL_MODES}
                idBase="bulk-quick-mode"
              />
            }
          />

          <FieldRow
            label="Terminal font"
            help="Set a family, or Clear to return every selected device to the global font."
            control={
              <ModeButtons
                value={fontFamilyMode}
                onChange={setFontFamilyMode}
                options={CLEARABLE_MODES}
                idBase="bulk-font-family-mode"
              />
            }
            value={
              fontFamilyMode === "set" ? (
                <>
                  <Input
                    value={fontFamilyValue}
                    onChange={(e) => setFontFamilyValue(e.target.value)}
                    placeholder="e.g. JetBrains Mono"
                    aria-label="Terminal font family"
                    aria-invalid={fontFamilyInvalid}
                    list="bulk-font-families"
                    autoComplete="off"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                  />
                  <datalist id="bulk-font-families">
                    {(monospaceFonts.data ?? []).map((f) => (
                      <option key={f} value={f} />
                    ))}
                  </datalist>
                </>
              ) : undefined
            }
          />

          <FieldRow
            label="Font size"
            help={`${TERMINAL_FONT_SIZE_MIN}–${TERMINAL_FONT_SIZE_MAX} px; Clear returns to the global size.`}
            control={
              <ModeButtons
                value={fontSizeMode}
                onChange={setFontSizeMode}
                options={CLEARABLE_MODES}
                idBase="bulk-font-size-mode"
              />
            }
            value={
              fontSizeMode === "set" ? (
                <Input
                  type="number"
                  value={fontSizeValue}
                  onChange={(e) => setFontSizeValue(e.target.valueAsNumber || 0)}
                  min={TERMINAL_FONT_SIZE_MIN}
                  max={TERMINAL_FONT_SIZE_MAX}
                  step={1}
                  aria-label="Terminal font size"
                  aria-invalid={fontSizeInvalid}
                />
              ) : undefined
            }
          />
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => void apply()}
            disabled={applyDisabled}
            data-testid="bulk-apply"
          >
            {bulk.isPending ? "Applying…" : `Apply to ${devices.length} devices`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
