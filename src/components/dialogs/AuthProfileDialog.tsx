import { useEffect, useRef, useState } from "react";

import { zodResolver } from "@hookform/resolvers/zod";
// Aliased: the component's `open` prop (a boolean) shadows this name.
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { useForm } from "react-hook-form";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
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
import type { AuthProfileInput, SecretRefInput } from "@/lib/api";
import { useBackendAvailabilityFor } from "@/lib/availability";
import { useAddAuthProfile, useEnrollSecret, useUpdateAuthProfile } from "@/lib/mutations";
import {
  authProfileFormSchema,
  type AuthProfileFormValues,
  SUPPORTED_BACKENDS,
} from "@/lib/schemas";
import { toastSuccess } from "@/lib/toast";

export interface AuthProfileDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** "add" creates a new profile; "edit" updates an existing one. */
  mode: "add" | "edit";
  /** Required when `mode === "edit"`; ignored on "add". */
  existingName?: string;
  /** Optional metadata used to prefill non-secret fields (username,
   *  backend kind, ssh_key file path) when `mode === "edit"`.
   *  Secret-bearing fields (keyring key, op reference, passphrase)
   *  stay blank — Rule 1 says IPC never returns secrets to the
   *  frontend, so we ask the user to re-enter them. `key_path` is a
   *  filesystem reference, not a secret (same footing as
   *  `suggestion.ssh_key_path`), so editing an ssh_key profile no
   *  longer forces a re-Browse for a path the inventory already
   *  knows (v1.6.0 follow-up, #116). */
  existingMeta?: { username: string; backend: string; key_path?: string | null };
  /** Add-mode prefill from a detected import identity. Seeds the
   *  (non-secret) backend kind, key-file path, and username so the user
   *  doesn't re-type what the importer already found. Ignored in edit
   *  mode; secret-bearing fields stay blank (Rule 1 — `ssh_key_path` is a
   *  path reference, not a secret, same as `existingMeta`'s backend kind). */
  suggestion?: { backend?: string; ssh_key_path?: string; username?: string };
  /** Called with the chosen name when an Add succeeds. The Add Device
   *  dialog uses this to set its `auth` field to the freshly-created
   *  profile. */
  onCreated?: (name: string) => void;
  /** Phase 7a C14 — when true, focus the secret-value field on open.
   *  Used by the manager row's "Set value" action so the user lands
   *  directly on the input without manually clicking. */
  focusSecretValueOnOpen?: boolean;
}

/**
 * Add or edit an auth profile. The dialog supports keyring, ssh_agent,
 * `ssh_key` (a private key file on disk, with an optional passphrase
 * enrolled to the keychain), op, and env. The last backend
 * (`encrypted_file`) still requires editing the inventory TOML directly.
 */
export function AuthProfileDialog({
  open,
  onOpenChange,
  mode,
  existingName,
  existingMeta,
  suggestion,
  onCreated,
  focusSecretValueOnOpen,
}: AuthProfileDialogProps) {
  const [submitError, setSubmitError] = useState<string | null>(null);
  const secretInputRef = useRef<HTMLInputElement | null>(null);

  const initialBackend = resolveInitialBackend(mode, existingMeta, suggestion);

  const form = useForm<AuthProfileFormValues>({
    resolver: zodResolver(authProfileFormSchema),
    defaultValues: {
      name: existingName ?? "",
      username: existingMeta?.username ?? (mode === "add" ? (suggestion?.username ?? "") : ""),
      backend: initialBackend,
      keyring_key: "",
      ssh_agent_fingerprint: "",
      ssh_key_path:
        mode === "add" ? (suggestion?.ssh_key_path ?? "") : (existingMeta?.key_path ?? ""),
      ssh_key_passphrase: "",
      op_reference: "",
      env_var: "",
      secret_value: "",
    },
  });

  // Reset on open or mode change so add ↔ edit flows don't bleed
  // values. Trigger is a *prop change* (open / existingName /
  // existingMeta), not a user event — react-doctor's event-handler
  // rule doesn't fit.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (open) {
      const backend = resolveInitialBackend(mode, existingMeta, suggestion);
      form.reset({
        name: existingName ?? "",
        username: existingMeta?.username ?? (mode === "add" ? (suggestion?.username ?? "") : ""),
        backend,
        keyring_key: "",
        ssh_agent_fingerprint: "",
        ssh_key_path:
          mode === "add" ? (suggestion?.ssh_key_path ?? "") : (existingMeta?.key_path ?? ""),
        ssh_key_passphrase: "",
        op_reference: "",
        env_var: "",
        secret_value: "",
      });
      setSubmitError(null);
      if (focusSecretValueOnOpen) {
        // Defer focus until the input is mounted (backend === keyring
        // is the trigger). rAF inside rAF gives Radix a chance to
        // finish its open animation before we yank focus.
        requestAnimationFrame(() =>
          requestAnimationFrame(() => {
            secretInputRef.current?.focus();
          }),
        );
      }
    }
  }, [open, existingName, existingMeta, suggestion, mode, focusSecretValueOnOpen, form]);

  const addMutation = useAddAuthProfile();
  const updateMutation = useUpdateAuthProfile();
  const enrollMutation = useEnrollSecret();
  const pending = addMutation.isPending || updateMutation.isPending || enrollMutation.isPending;

  const backend = form.watch("backend");
  const backendAvailability = useBackendAvailabilityFor(backend);

  const onSubmit = (values: AuthProfileFormValues) => {
    setSubmitError(null);
    const profileName = mode === "add" ? values.name : (existingName ?? "");
    const input: AuthProfileInput = {
      username: values.username,
      secret: buildSecretRef(values, profileName),
    };
    const onError = (e: unknown) => setSubmitError(e instanceof Error ? e.message : String(e));

    // After the profile upsert lands, chain an `enrollSecret` call to
    // write the actual secret value to the OS keychain:
    //  - keyring: the typed password (`secret_value`)
    //  - ssh_key: the typed key passphrase (`ssh_key_passphrase`), which
    //    the backend's `lookup_profile_secret` routes into the profile's
    //    nested keyring ref.
    // Blank means "leave the existing value alone" in edit mode and
    // "create the reference without enrolling yet" in add mode.
    const enrollValue =
      values.backend === "keyring"
        ? (values.secret_value?.trim() ?? "")
        : values.backend === "ssh_key"
          ? (values.ssh_key_passphrase?.trim() ?? "")
          : "";
    const shouldEnroll = enrollValue.length > 0;

    const finalize = () => {
      if (!shouldEnroll) {
        onOpenChange(false);
        if (mode === "add") onCreated?.(values.name);
        return;
      }
      enrollMutation.mutate(
        { profileName, value: enrollValue },
        {
          onSuccess: () => {
            toastSuccess(values.backend === "ssh_key" ? "Passphrase saved" : "Secret enrolled", {
              description: `Stored in the OS keychain for "${profileName}".`,
            });
            onOpenChange(false);
            if (mode === "add") onCreated?.(values.name);
          },
          onError,
        },
      );
    };

    if (mode === "add") {
      addMutation.mutate(
        { name: values.name, input },
        {
          onSuccess: finalize,
          onError,
        },
      );
    } else {
      if (!existingName) {
        setSubmitError("Internal: edit mode requires existingName");
        return;
      }
      updateMutation.mutate(
        { name: existingName, input },
        {
          onSuccess: finalize,
          onError,
        },
      );
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{mode === "add" ? "New auth profile" : "Edit auth profile"}</DialogTitle>
          <DialogDescription>
            The profile is a <em>reference</em> to where the credential lives — the actual secret
            never enters the inventory file.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(e) => {
              // Stop SubmitEvent from bubbling to the AddDeviceDialog
              // parent form when this dialog is opened modal-on-modal
              // from the device-form's "+ New" button. Without this,
              // saving an auth profile would also submit the partially
              // filled device form.
              e.stopPropagation();
              form.handleSubmit(onSubmit)(e);
            }}
            className="grid gap-4"
          >
            {mode === "add" && (
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Transit Friendly Name</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="lab-pw"
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      Stable, human-readable identifier. Devices reference it by name.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Username</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="root"
                      autoComplete="off"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="backend"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Secret backend</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {SUPPORTED_BACKENDS.map((b) => (
                        <SelectItem key={b.value} value={b.value}>
                          {b.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {backendAvailability.status === "needs_install" && (
                    <div
                      className="mt-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200"
                      role="status"
                    >
                      <span className="font-semibold">⚠ </span>
                      {backendAvailability.hint}
                    </div>
                  )}
                  <FormMessage />
                </FormItem>
              )}
            />

            {backend === "keyring" && (
              <>
                <FormField
                  control={form.control}
                  name="keyring_key"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>OS Keyring Friendly Name</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="transit/lab-pw"
                          autoComplete="off"
                          autoCapitalize="none"
                          autoCorrect="off"
                          spellCheck={false}
                          {...field}
                        />
                      </FormControl>
                      <FormDescription>
                        The key the OS keystore looks up. The actual secret stays in the OS
                        keychain.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="secret_value"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Password Value</FormLabel>
                      <FormControl>
                        <Input
                          type="password"
                          placeholder={
                            mode === "edit"
                              ? "(leave blank to keep the existing value)"
                              : "Required to enroll; can fill later"
                          }
                          autoComplete="new-password"
                          autoCapitalize="none"
                          autoCorrect="off"
                          spellCheck={false}
                          data-testid="auth-profile-secret-value"
                          {...field}
                          ref={(el) => {
                            field.ref(el);
                            secretInputRef.current = el;
                          }}
                        />
                      </FormControl>
                      <FormDescription>
                        Written to the OS keychain via `enroll_secret` after the profile is saved.
                        Never round-trips back over IPC.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}

            {backend === "prompt" && (
              <div className="rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
                <p className="font-medium text-foreground">Nothing is stored</p>
                <p className="mt-1">
                  Transit will ask for the credential each time you connect and keep it only for
                  that connection — no keychain entry, no file. This is the backend to use for
                  one-time codes (TOTP, RSA, Duo), PAM/CyberArk account menus, or any device whose
                  policy forbids stored passwords.
                </p>
                <p className="mt-2">
                  Devices using this profile are skipped by “Launch all” — each one needs you
                  present to answer its prompt.
                </p>
              </div>
            )}

            {backend === "ssh_agent" && (
              <FormField
                control={form.control}
                name="ssh_agent_fingerprint"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Public-key fingerprint (optional)</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="SHA256:..."
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      Pin to a specific agent key. Leave blank to let the agent pick.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {backend === "op" && (
              <FormField
                control={form.control}
                name="op_reference"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>1Password reference</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="op://Vault/Item/password"
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {backend === "env" && (
              <FormField
                control={form.control}
                name="env_var"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Environment variable name</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="TRANSIT_LAB_PW"
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      Headless / CI use. Not recommended for interactive desktop.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {backend === "ssh_key" && (
              <>
                <FormField
                  control={form.control}
                  name="ssh_key_path"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Private key file</FormLabel>
                      <div className="flex gap-2">
                        <FormControl>
                          <Input
                            placeholder="~/.ssh/id_ed25519"
                            autoComplete="off"
                            autoCapitalize="none"
                            autoCorrect="off"
                            spellCheck={false}
                            {...field}
                          />
                        </FormControl>
                        <Button
                          type="button"
                          variant="outline"
                          onClick={() => {
                            void openFileDialog({
                              multiple: false,
                              directory: false,
                              title: "Choose your SSH private key",
                            })
                              .then((picked) => {
                                if (typeof picked === "string") field.onChange(picked);
                              })
                              .catch(() => {});
                          }}
                        >
                          Browse…
                        </Button>
                      </div>
                      <FormDescription>
                        OpenSSH, PEM, or PuTTY .ppk. The file stays on disk — only its path is
                        saved.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="ssh_key_passphrase"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Key passphrase (only if encrypted)</FormLabel>
                      <FormControl>
                        <Input
                          type="password"
                          placeholder={
                            mode === "edit"
                              ? "(blank = keep / unencrypted)"
                              : "Leave blank for an unencrypted key"
                          }
                          autoComplete="new-password"
                          autoCapitalize="none"
                          autoCorrect="off"
                          spellCheck={false}
                          {...field}
                        />
                      </FormControl>
                      <FormDescription>
                        Saved to the OS keychain after the profile is created. Never enters the
                        inventory file.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}

            {submitError && (
              <p className="text-sm text-destructive" role="alert">
                {submitError}
              </p>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={pending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? "Saving..." : "Save"}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

type SupportedBackend = (typeof SUPPORTED_BACKENDS)[number]["value"];

function isSupportedBackend(backend: string): backend is SupportedBackend {
  return SUPPORTED_BACKENDS.some((b) => b.value === backend);
}

/** Resolve the backend the form should open on. Edit mode trusts the
 *  existing profile's backend; add mode honors an import suggestion;
 *  otherwise default to keyring. */
function resolveInitialBackend(
  mode: "add" | "edit",
  existingMeta: { backend: string } | undefined,
  suggestion: { backend?: string } | undefined,
): SupportedBackend {
  if (existingMeta && isSupportedBackend(existingMeta.backend)) return existingMeta.backend;
  if (mode === "add" && suggestion?.backend && isSupportedBackend(suggestion.backend)) {
    return suggestion.backend;
  }
  return "keyring";
}

function buildSecretRef(v: AuthProfileFormValues, profileName: string): SecretRefInput {
  switch (v.backend) {
    case "keyring":
      return { backend: "keyring", key: v.keyring_key!.trim() };
    case "ssh_agent":
      return {
        backend: "ssh_agent",
        public_key_fingerprint:
          v.ssh_agent_fingerprint && v.ssh_agent_fingerprint.trim() !== ""
            ? v.ssh_agent_fingerprint.trim()
            : null,
      };
    case "ssh_key": {
      // Encrypted key (passphrase typed) → the passphrase rides a nested
      // keyring ref keyed off the profile name; its value is enrolled
      // separately via `enroll_secret`. Unencrypted → no nested ref.
      const hasPassphrase = (v.ssh_key_passphrase?.trim() ?? "").length > 0;
      return {
        backend: "ssh_key",
        path: v.ssh_key_path!.trim(),
        passphrase: hasPassphrase
          ? { backend: "keyring", key: `transit/${profileName}-passphrase` }
          : null,
      };
    }
    case "op":
      return { backend: "op", reference: v.op_reference!.trim() };
    case "env":
      return { backend: "env", var: v.env_var!.trim() };
    // Nothing to reference: the credential is typed at connect time and
    // never stored. `enrollValue` above is already "" for this backend,
    // so no enrollment is chained either.
    case "prompt":
      return { backend: "prompt" };
  }
}
