import { useState } from "react";

import { useQuery } from "@tanstack/react-query";
import { Check, X } from "lucide-react";
import type { Control } from "react-hook-form";
import { useWatch } from "react-hook-form";

import { DeviceColorPicker } from "@/components/dialogs/DeviceColorPicker";
import { GroupCombobox } from "@/components/dialogs/GroupCombobox";
import { JumpHostCombobox } from "@/components/dialogs/JumpHostCombobox";
import { VendorCombobox } from "@/components/dialogs/VendorCombobox";
import { Checkbox } from "@/components/ui/checkbox";
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { listDevices, testSecretResolve, type AuthProfileMeta } from "@/lib/api";
import { loadSelectableMonospaceFonts } from "@/lib/fonts";
import { type DeviceFormValues } from "@/lib/schemas";

/** Inputs we never want the OS / browser to autocapitalize, autocorrect,
 *  or spellcheck. `id`/`host`/`group` etc. are technical identifiers,
 *  not prose. */
const noAutoFormat = {
  autoComplete: "off",
  autoCapitalize: "none",
  autoCorrect: "off",
  spellCheck: false,
} as const;

/**
 * v4.1.0 — the device form is split into named SECTION groups so the Edit
 * dialog can present them as a left-nav shell (mirroring SettingsDialog),
 * while the Add dialog renders them flat in one column. These section
 * components are the single source of truth for the field JSX — both
 * dialogs compose them, so a new field is added in exactly one place.
 *
 * `SECTION_FOR_FIELD` maps each RHF field name to its section id; the Edit
 * shell uses it to jump to the section holding the first validation error
 * on Save, so an error is never stranded on a hidden pane.
 */
export const DEVICE_SECTIONS = [
  { id: "connection", label: "Connection" },
  { id: "organization", label: "Organization" },
  { id: "appearance", label: "Appearance" },
  { id: "terminal", label: "Terminal" },
] as const;

export type DeviceSectionId = (typeof DEVICE_SECTIONS)[number]["id"];

export const SECTION_FOR_FIELD: Record<keyof DeviceFormValues, DeviceSectionId> = {
  id: "connection",
  host: "connection",
  port: "connection",
  vendor: "connection",
  auth: "connection",
  group: "organization",
  tags: "organization",
  color: "appearance",
  bold_color: "appearance",
  font_family: "appearance",
  font_size: "appearance",
  syntax_highlighting: "terminal",
  quick_copy_paste: "terminal",
  jump_via: "connection",
  forward_agent: "connection",
};

export interface DeviceFormFieldsProps {
  control: Control<DeviceFormValues>;
  authProfiles: AuthProfileMeta[];
  /** Existing group paths (full + every prefix). Rendered as a
   *  `<datalist>` so the group `<Input>` shows native autocomplete. */
  existingGroups: string[];
  /** Called when the user clicks "+ New auth profile". The dialog's
   *  parent should open the AuthProfileDialog without closing the
   *  device dialog. */
  onCreateAuthProfile: () => void;
}

/** Chip editor for a device's free-form tags. Enter / comma adds; Backspace
 *  on an empty input removes the last chip; the × removes a specific one. */
function TagsInput({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const [text, setText] = useState("");
  const add = () => {
    const t = text.trim();
    if (t && !value.includes(t)) onChange([...value, t]);
    setText("");
  };
  return (
    <div className="flex flex-wrap items-center gap-1 rounded-md border border-input bg-background px-2 py-1">
      {value.map((tag) => (
        <span key={tag} className="flex items-center gap-1 rounded bg-accent px-1.5 py-0.5 text-xs">
          {tag}
          <button
            type="button"
            onClick={() => onChange(value.filter((x) => x !== tag))}
            aria-label={`Remove tag ${tag}`}
            className="text-muted-foreground hover:text-destructive"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            add();
          } else if (e.key === "Backspace" && text === "" && value.length > 0) {
            onChange(value.slice(0, -1));
          }
        }}
        onBlur={add}
        placeholder={value.length === 0 ? "Add tags (Enter)" : ""}
        className="min-w-20 flex-1 bg-transparent text-sm outline-none"
        data-testid="tags-input"
        {...noAutoFormat}
      />
    </div>
  );
}

/** Connection section: identity + transport + credential. */
export function ConnectionFields({
  control,
  authProfiles,
  onCreateAuthProfile,
}: {
  control: Control<DeviceFormValues>;
  authProfiles: AuthProfileMeta[];
  onCreateAuthProfile: () => void;
}) {
  return (
    <div className="grid gap-4">
      <FormField
        control={control}
        name="id"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Friendly Name</FormLabel>
            <FormControl>
              <Input placeholder="Router1" {...noAutoFormat} {...field} />
            </FormControl>
            <FormDescription>
              Unique within the inventory — shown on the session tab.
            </FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />

      <div className="grid grid-cols-[1fr_120px] gap-3">
        <FormField
          control={control}
          name="host"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Host</FormLabel>
              <FormControl>
                <Input placeholder="192.0.2.35" {...noAutoFormat} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={control}
          name="port"
          render={({ field }) => (
            <FormItem>
              <FormLabel>SSH Port</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  min={1}
                  max={65535}
                  // The HTML number input gives `field.onChange` a
                  // string by default; the schema is `z.number()`,
                  // so route through `valueAsNumber`. NaN (cleared
                  // input) propagates and the schema's `.int()`
                  // surfaces a validation error — matches how the
                  // form behaved before but without the
                  // `z.coerce.number()` resolver-type asymmetry.
                  {...field}
                  onChange={(e) => field.onChange(e.target.valueAsNumber)}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      <FormField
        control={control}
        name="vendor"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Vendor — Policy Gate</FormLabel>
            <FormControl>
              <VendorCombobox value={field.value} onChange={field.onChange} />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />

      <FormField
        control={control}
        name="auth"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Auth profile</FormLabel>
            <div className="flex gap-2">
              <Select onValueChange={field.onChange} value={field.value}>
                <FormControl>
                  <SelectTrigger className="flex-1">
                    <SelectValue placeholder="Pick an auth profile" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {authProfiles.length === 0 ? (
                    <div className="px-2 py-1.5 text-xs text-muted-foreground">
                      No profiles yet — create one with "+ New".
                    </div>
                  ) : (
                    authProfiles.map((p) => (
                      <SelectItem key={p.name} value={p.name}>
                        <span className="font-mono">{p.name}</span>
                        <span className="ml-2 text-xs text-muted-foreground">
                          {p.username}@{p.backend}
                        </span>
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
              <button
                type="button"
                onClick={onCreateAuthProfile}
                className="rounded-md border border-input bg-background px-3 text-xs hover:bg-accent"
              >
                + New
              </button>
            </div>
            <AuthProfileActions control={control} authProfiles={authProfiles} />
            <FormMessage />
          </FormItem>
        )}
      />

      <JumpHostField control={control} />

      <FormField
        control={control}
        name="forward_agent"
        render={({ field }) => (
          <FormItem className="flex flex-row items-start gap-2 space-y-0">
            <FormControl>
              <Checkbox id="forward-agent" checked={field.value} onCheckedChange={field.onChange} />
            </FormControl>
            <div className="flex-1 space-y-1 leading-none">
              <FormLabel htmlFor="forward-agent" className="cursor-pointer font-normal">
                Forward SSH agent
              </FormLabel>
              <FormDescription className="text-xs">
                Let programs on this host authenticate with your local SSH agent (for a bastion you
                work on — not needed for the jump-host setting above).
              </FormDescription>
              <FormDescription className="text-xs text-amber-600 dark:text-amber-500">
                While connected, an administrator on this host can use every key your agent holds.
                Enable only on hosts you trust.
              </FormDescription>
            </div>
          </FormItem>
        )}
      />
    </div>
  );
}

/**
 * Jump host picker (v6.5.0): a Select over the OTHER inventory devices,
 * mirroring the auth-profile select (mono id + muted host:port). The
 * option list excludes this device and any device whose own jump chain
 * leads back here — a UX guard only; the backend loader/mutator is the
 * enforcement (existence, self-reference, cycles, depth). A stored
 * reference the form can't resolve (hand-edited transit.toml) still
 * renders as a selectable "(unknown)" item so the form stays
 * submittable — the `color` graceful-fallback contract.
 */
function JumpHostField({ control }: { control: Control<DeviceFormValues> }) {
  const ownId = useWatch({ control, name: "id" });
  const { data: devices = [] } = useQuery({ queryKey: ["devices"], queryFn: listDevices });

  const jumpOf = new Map(devices.filter((d) => d.jump_via).map((d) => [d.id, d.jump_via]));
  /** Walk a device's jump chain (bounded — a hand-edited cycle must not
   *  hang the render; the backend refuses such files outright). */
  const chainOf = (startId: string): string[] => {
    const chain: string[] = [];
    const seen = new Set<string>();
    let cursor: string | null | undefined = startId;
    while (cursor && chain.length < 8 && !seen.has(cursor)) {
      seen.add(cursor);
      chain.push(cursor);
      cursor = jumpOf.get(cursor);
    }
    return chain;
  };
  const eligible = devices.filter((d) => d.id !== ownId && !chainOf(d.id).includes(ownId));

  return (
    <FormField
      control={control}
      name="jump_via"
      render={({ field }) => {
        // Path preview, outermost hop first: You → … → jump → this device.
        const preview = field.value ? [...chainOf(field.value)].reverse() : [];
        return (
          <FormItem>
            <FormLabel>Jump host</FormLabel>
            <div className="flex gap-2">
              <FormControl>
                <div className="flex-1">
                  <JumpHostCombobox
                    value={field.value}
                    onChange={field.onChange}
                    options={eligible.map((d) => ({ id: d.id, host: d.host, port: d.port }))}
                    allowDirect
                    data-testid="jump-via-trigger"
                  />
                </div>
              </FormControl>
              {field.value !== "" && (
                // One-click reset (smoke-test finding: with a large
                // inventory, "back to direct" must not require finding
                // a row in the list).
                <button
                  type="button"
                  onClick={() => field.onChange("")}
                  aria-label="Reset to direct connection"
                  title="Reset to direct connection"
                  className="rounded-md border border-input bg-background px-3 text-xs hover:bg-accent"
                  data-testid="jump-via-clear"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
            <FormDescription className="text-xs">
              {field.value ? (
                <>Path: You &rarr; {preview.join(" → ")} &rarr; this device</>
              ) : (
                <>Tunnel this connection through another inventory device (SSH ProxyJump).</>
              )}
            </FormDescription>
            <FormMessage />
          </FormItem>
        );
      }}
    />
  );
}

/** Organization section: sidebar grouping + free-form tags. */
export function OrganizationFields({
  control,
  existingGroups,
}: {
  control: Control<DeviceFormValues>;
  existingGroups: string[];
}) {
  return (
    <div className="grid gap-4">
      <FormField
        control={control}
        name="group"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Group/Folder</FormLabel>
            <FormControl>
              <GroupCombobox
                value={field.value}
                onChange={field.onChange}
                existingGroups={existingGroups}
              />
            </FormControl>
            <FormDescription>
              Pick an existing group, or type a new path and choose <em>Create</em>. Use
              <code>/</code> to nest.
            </FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />

      <FormField
        control={control}
        name="tags"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Tags</FormLabel>
            <FormControl>
              <TagsInput value={field.value} onChange={field.onChange} />
            </FormControl>
            <FormDescription>
              Free-form labels for filtering — e.g. prod, core, datacenter-3. Enter to add.
            </FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />
    </div>
  );
}

/** Appearance section (v4.1.0): per-device accent color + a louder "bold"
 *  tint, plus a per-device terminal font family + size override. */
export function AppearanceFields({ control }: { control: Control<DeviceFormValues> }) {
  // OS-detected + webview-renderable monospace families, for the font
  // datalist. Shares the ["monospaceFonts"] cache with Settings.
  const { data: fonts } = useQuery({
    queryKey: ["monospaceFonts"],
    queryFn: loadSelectableMonospaceFonts,
  });

  return (
    <div className="grid gap-4">
      <FormField
        control={control}
        name="color"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Accent color</FormLabel>
            <FormControl>
              <DeviceColorPicker value={field.value} onChange={field.onChange} />
            </FormControl>
            <FormDescription>
              A quick visual cue for which device you are on — tints the sidebar row, session tab,
              and terminal edge. Optional.
            </FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />

      <FormField
        control={control}
        name="bold_color"
        render={({ field }) => (
          <FormItem className="flex flex-row items-start gap-2 space-y-0">
            <FormControl>
              <Checkbox id="bold-color" checked={field.value} onCheckedChange={field.onChange} />
            </FormControl>
            <div className="flex-1 space-y-1 leading-none">
              <FormLabel htmlFor="bold-color" className="cursor-pointer font-normal">
                Bold accent
              </FormLabel>
              <FormDescription className="text-xs">
                Render the accent as a louder background tint on the session tab and pane, not just
                the thin edge. Needs an accent color set above.
              </FormDescription>
            </div>
          </FormItem>
        )}
      />

      <FormField
        control={control}
        name="font_family"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Terminal font</FormLabel>
            <FormControl>
              <Input
                list="device-font-families"
                placeholder="Use the global font"
                {...noAutoFormat}
                {...field}
              />
            </FormControl>
            <datalist id="device-font-families">
              {(fonts ?? []).map((f) => (
                <option key={f} value={f} />
              ))}
            </datalist>
            <FormDescription>
              Override the terminal font for this device only. Leave blank to use the global font
              (Settings → General).
            </FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />

      <FormField
        control={control}
        name="font_size"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Font size</FormLabel>
            <FormControl>
              <Input
                type="number"
                min={0}
                max={32}
                className="w-28"
                placeholder="Global"
                {...field}
                // 0 = "use the global size"; show it as an empty box so the
                // "Global" placeholder reads, and map a cleared box back to 0.
                value={field.value === 0 ? "" : field.value}
                onChange={(e) => field.onChange(e.target.value === "" ? 0 : e.target.valueAsNumber)}
              />
            </FormControl>
            <FormDescription>Blank uses the global size; otherwise 8–32.</FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />
    </div>
  );
}

/** Terminal section: per-device rendering + copy/paste behavior. */
export function TerminalFields({ control }: { control: Control<DeviceFormValues> }) {
  return (
    <div className="grid gap-4">
      <FormField
        control={control}
        name="syntax_highlighting"
        render={({ field }) => (
          <FormItem className="flex flex-row items-start gap-2 space-y-0">
            <FormControl>
              <Checkbox
                id="syntax-highlighting"
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            </FormControl>
            <div className="flex-1 space-y-1 leading-none">
              <FormLabel htmlFor="syntax-highlighting" className="cursor-pointer font-normal">
                Syntax highlighting
              </FormLabel>
              <FormDescription className="text-xs">
                Color interface states, BGP states, IP/MAC/VLAN, and severity keywords. Per-device —
                other connections are unaffected.
              </FormDescription>
            </div>
          </FormItem>
        )}
      />

      <FormField
        control={control}
        name="quick_copy_paste"
        render={({ field }) => (
          <FormItem className="flex flex-row items-start gap-2 space-y-0">
            <FormControl>
              <Checkbox
                id="quick-copy-paste"
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            </FormControl>
            <div className="flex-1 space-y-1 leading-none">
              <FormLabel htmlFor="quick-copy-paste" className="cursor-pointer font-normal">
                Quick copy/paste
              </FormLabel>
              <FormDescription className="text-xs">
                Auto-copy selected text to the clipboard; middle-click and right-click paste.
                Multi-line pastes still confirm.
              </FormDescription>
            </div>
          </FormItem>
        )}
      />
    </div>
  );
}

/**
 * Flat composite — all sections in one column. Used by the Add dialog
 * (create flow stays a single simple form). The Edit dialog composes the
 * same section components into a left-nav shell instead.
 */
export function DeviceFormFields({
  control,
  authProfiles,
  existingGroups,
  onCreateAuthProfile,
}: DeviceFormFieldsProps) {
  return (
    <div className="grid gap-4">
      <ConnectionFields
        control={control}
        authProfiles={authProfiles}
        onCreateAuthProfile={onCreateAuthProfile}
      />
      <OrganizationFields control={control} existingGroups={existingGroups} />
      <AppearanceFields control={control} />
      <TerminalFields control={control} />
    </div>
  );
}

/**
 * Below the auth-profile select, render a per-backend action:
 * - ssh_agent / op: "Test connection" → calls testSecretResolve
 * - env: helper text only
 * - keyring: nothing — Phase 7a C14 moved "Set value..." into the
 *   AuthProfileDialog itself, since secret enrollment is a property
 *   of the credential, not the device.
 *
 * Reads the currently-selected profile name via `useWatch` and looks
 * up its backend from the authProfiles list. Empty string (no
 * selection) → no action visible.
 */
function AuthProfileActions({
  control,
  authProfiles,
}: {
  control: Control<DeviceFormValues>;
  authProfiles: AuthProfileMeta[];
}) {
  const selectedName = useWatch({ control, name: "auth" });
  const [testState, setTestState] = useState<
    | { status: "idle" }
    | { status: "pending" }
    | { status: "ok"; length: number }
    | { status: "err"; message: string }
  >({ status: "idle" });

  if (!selectedName) return null;
  const profile = authProfiles.find((p) => p.name === selectedName);
  if (!profile) return null;

  const runTest = async () => {
    setTestState({ status: "pending" });
    try {
      const ok = await testSecretResolve(selectedName);
      setTestState({ status: "ok", length: ok.length });
    } catch (e) {
      setTestState({
        status: "err",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  return (
    <div className="mt-2 space-y-2 text-xs">
      {(profile.backend === "ssh_agent" || profile.backend === "op") && (
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={runTest}
              disabled={testState.status === "pending"}
              className="rounded-md border border-input bg-background px-2 py-1 hover:bg-accent disabled:opacity-50"
            >
              {testState.status === "pending" ? "Testing..." : "Test connection"}
            </button>
            {testState.status === "ok" &&
              (profile.backend === "ssh_agent" ? (
                <span className="flex items-center gap-1 text-emerald-600">
                  <Check className="h-3.5 w-3.5" /> Agent reachable.
                </span>
              ) : (
                <span className="flex items-center gap-1 text-emerald-600">
                  <Check className="h-3.5 w-3.5" /> Resolved value ({testState.length} bytes).
                </span>
              ))}
          </div>
          {testState.status === "err" && (
            <div
              className="flex items-start gap-1 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-destructive"
              role="alert"
            >
              <X className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span className="break-words">{testState.message}</span>
            </div>
          )}
        </div>
      )}
      {profile.backend === "env" && (
        <p className="text-muted-foreground">
          Set the env var before launching Transit. Verify in a shell:{" "}
          <code className="rounded bg-muted px-1">echo $VAR</code>.
        </p>
      )}
    </div>
  );
}
