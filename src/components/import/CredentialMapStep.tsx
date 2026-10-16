import { useEffect, useMemo, useState } from "react";

import { useMutation, useQuery } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";

import { AuthProfileDialog } from "@/components/dialogs/AuthProfileDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  addAuthProfile,
  enrollSecret,
  probeSshKeys,
  type AuthProfileMeta,
  type ImportIdentityMeta,
  type KeyProbeVerdict,
  type SecretRefInput,
} from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { toastError, toastSuccess } from "@/lib/toast";

import type { ImportAction, ImportState } from "./importReducer";

function describeSuggestion(id: ImportIdentityMeta): string {
  if (id.suggested_backend === "ssh_key") {
    return id.key_path ? `SSH key — ${id.key_path}` : "SSH key";
  }
  if (id.suggested_backend === "ssh_agent") return "Public-key / SSH agent — no secret to enter";
  return "Password — you'll enroll it once";
}

/** Lowercase the login and strip it to the auth-profile name charset
 *  (`[a-z0-9_-]`, per `authProfileFormSchema.name`), deduping against
 *  names already taken (existing profiles + earlier in this batch). The
 *  derived name also keys the nested `transit/<name>-passphrase` keyring
 *  entry, so uniqueness here keeps passphrases from colliding. */
function uniqueProfileName(login: string, taken: Set<string>): string {
  const base =
    login
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "") || "key";
  let candidate = base;
  let n = 2;
  while (taken.has(candidate)) {
    candidate = `${base}-${n}`;
    n += 1;
  }
  return candidate;
}

export function CredentialMapStep({
  state,
  dispatch,
  profiles,
}: {
  state: ImportState;
  dispatch: React.Dispatch<ImportAction>;
  profiles: AuthProfileMeta[];
}) {
  const [createFor, setCreateFor] = useState<string | null>(null);
  // Transient per-encrypted-key passphrases. NEVER persisted to the
  // reducer (matches "a passphrase never enters wizard state"); they
  // exist only to feed `enroll_secret` during a batch create.
  const [passphrases, setPassphrases] = useState<Record<string, string>>({});

  // Unique on-disk key paths referenced by ssh_key identities — probed
  // once (read-only) so we know which are encrypted / unparseable /
  // missing on this machine. Verdict-only; no key bytes cross IPC.
  const keyPaths = useMemo(() => {
    const set = new Set<string>();
    for (const id of state.identities) {
      if (id.suggested_backend === "ssh_key" && id.key_path) set.add(id.key_path);
    }
    return [...set].sort();
  }, [state.identities]);

  const probeQuery = useQuery({
    queryKey: ["sshKeyProbe", keyPaths],
    queryFn: () => probeSshKeys(keyPaths),
    enabled: keyPaths.length > 0,
    staleTime: Infinity, // key files don't change mid-wizard
  });

  const verdicts = useMemo(() => {
    const m = new Map<string, KeyProbeVerdict>();
    for (const p of probeQuery.data ?? []) m.set(p.path, p.verdict);
    return m;
  }, [probeQuery.data]);

  // Reuse-existing is first-class: when a profile's username matches the
  // login (the "I already made a profile while evaluating" case),
  // pre-select it so the user lands on it with zero clicks.
  useEffect(() => {
    for (const id of state.identities) {
      if (state.credentialChoices[id.key]) continue;
      const match = profiles.find((p) => p.username === id.login);
      if (match) dispatch({ type: "SET_CREDENTIAL", identityKey: id.key, profileName: match.name });
    }
    // Re-run when the profile list changes (e.g. after a batch create).
  }, [profiles, state.identities]);

  const verdictFor = (id: ImportIdentityMeta): KeyProbeVerdict | undefined =>
    id.suggested_backend === "ssh_key" && id.key_path ? verdicts.get(id.key_path) : undefined;

  // An identity is batch-creatable when it needs no typed secret:
  //  - ssh_agent (no secret at all)
  //  - unencrypted ssh_key
  //  - encrypted ssh_key WITH a passphrase typed in its inline field
  // Already-mapped, password, and unparseable/missing keys are excluded.
  const isEligible = (id: ImportIdentityMeta): boolean => {
    if (state.credentialChoices[id.key]) return false;
    if (id.suggested_backend === "ssh_agent") return true;
    if (id.suggested_backend !== "ssh_key" || !id.key_path) return false;
    const v = verdicts.get(id.key_path);
    if (!v) return false;
    if (v.status === "unencrypted") return true;
    if (v.status === "encrypted") return (passphrases[id.key]?.trim().length ?? 0) > 0;
    return false; // unparseable / unreadable
  };

  const eligible = state.identities.filter(isEligible);
  // Encrypted keys still waiting on a passphrase before they can batch.
  const encryptedPending = state.identities.filter(
    (id) =>
      !state.credentialChoices[id.key] &&
      verdictFor(id)?.status === "encrypted" &&
      (passphrases[id.key]?.trim().length ?? 0) === 0,
  ).length;

  // One-click batch. Loops the raw add/enroll IPCs (not the per-profile
  // mutation hooks, which would fire a toast each) and invalidates +
  // toasts once. No change to `import_connections`; the only secret that
  // moves is each encrypted-key passphrase, via the sanctioned
  // `enroll_secret` channel — never the import payload.
  const batchMutation = useMutation({
    mutationFn: async () => {
      const taken = new Set(profiles.map((p) => p.name));
      let created = 0;
      const failures: string[] = [];
      for (const id of state.identities.filter(isEligible)) {
        const name = uniqueProfileName(id.login, taken);
        taken.add(name);
        try {
          let secret: SecretRefInput;
          let passphrase = "";
          if (id.suggested_backend === "ssh_agent") {
            secret = { backend: "ssh_agent", public_key_fingerprint: null };
          } else {
            const encrypted = id.key_path
              ? verdicts.get(id.key_path)?.status === "encrypted"
              : false;
            passphrase = passphrases[id.key]?.trim() ?? "";
            secret = {
              backend: "ssh_key",
              path: id.key_path!,
              passphrase: encrypted
                ? { backend: "keyring", key: `transit/${name}-passphrase` }
                : null,
            };
          }
          await addAuthProfile(name, { username: id.login, secret });
          // Encrypted key → its passphrase lands in the OS keychain.
          if (passphrase.length > 0) await enrollSecret(name, passphrase);
          dispatch({ type: "SET_CREDENTIAL", identityKey: id.key, profileName: name });
          created += 1;
        } catch (e) {
          failures.push(`${id.login}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      return { created, failures };
    },
    onSuccess: ({ created, failures }) => {
      void queryClient.invalidateQueries({ queryKey: ["authProfiles"] });
      if (created > 0) toastSuccess(`Created ${created} key profile${created === 1 ? "" : "s"}`);
      if (failures.length > 0) {
        toastError(
          `${failures.length} profile${failures.length === 1 ? "" : "s"} couldn't be created`,
          { description: failures.join(" · ") },
        );
      }
    },
    onError: (err) =>
      toastError(`Couldn't create profiles: ${err instanceof Error ? err.message : String(err)}`),
  });

  // Stable suggestion for the manual "+ New" dialog — memoized per open
  // identity so it doesn't re-trigger the dialog's reset effect.
  const suggestion = useMemo(() => {
    if (createFor === null) return undefined;
    const id = state.identities.find((i) => i.key === createFor);
    if (!id) return undefined;
    return {
      backend: id.suggested_backend,
      ssh_key_path: id.key_path ?? undefined,
      username: id.login,
    };
  }, [createFor, state.identities]);

  return (
    <div className="flex h-full flex-col">
      <div className="shrink-0 border-b border-border px-6 py-5">
        <h2 className="text-xl font-semibold tracking-tight">Map credentials</h2>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          {state.identities.length} distinct {state.identities.length === 1 ? "login" : "logins"}{" "}
          across {state.rows.length} connections. Key- and agent-based logins can be created for you
          in one click; point password logins at a profile (reuse one, or create a new one — you
          enter the secret once and it goes straight to your OS keychain).
        </p>

        {(eligible.length > 0 || encryptedPending > 0) && (
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/40 px-4 py-3">
            <p className="text-sm">
              {eligible.length > 0 ? (
                <>
                  <span className="font-medium">{eligible.length}</span> key / agent{" "}
                  {eligible.length === 1 ? "login is" : "logins are"} ready to create automatically.
                </>
              ) : (
                "Enter the passphrases below to create your encrypted-key profiles."
              )}
              {encryptedPending > 0 && (
                <span className="text-muted-foreground">
                  {" "}
                  {encryptedPending} encrypted {encryptedPending === 1 ? "key needs" : "keys need"}{" "}
                  a passphrase below.
                </span>
              )}
            </p>
            <Button
              type="button"
              size="sm"
              onClick={() => batchMutation.mutate()}
              disabled={batchMutation.isPending || eligible.length === 0}
              data-testid="cred-batch-create"
            >
              {batchMutation.isPending
                ? "Creating…"
                : `Create ${eligible.length} key profile${eligible.length === 1 ? "" : "s"}`}
            </Button>
          </div>
        )}

        {probeQuery.isError && (
          <p className="mt-2 text-xs text-amber-600 dark:text-amber-500">
            Couldn't check your key files — you can still create profiles manually with “+ New”.
          </p>
        )}
      </div>

      <ul className="min-h-0 flex-1 divide-y divide-border overflow-y-auto px-6 py-2">
        {state.identities.map((id) => {
          const chosen = state.credentialChoices[id.key] ?? "";
          const verdict = verdictFor(id);
          const showPassphrase = !chosen && verdict?.status === "encrypted";
          return (
            <li key={id.key} className="flex flex-col gap-2 py-3">
              <div className="flex items-center gap-3">
                <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
                  <KeyRound className="h-4 w-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm">
                    <span className="font-mono font-medium">{id.login}</span>
                    <span className="ml-2 text-xs text-muted-foreground">
                      {id.count} {id.count === 1 ? "device" : "devices"}
                    </span>
                  </div>
                  <div
                    className="break-all text-xs text-muted-foreground"
                    title={id.key_path ?? undefined}
                  >
                    {describeSuggestion(id)}
                  </div>
                </div>
                <VerdictBadge id={id} verdict={verdict} pending={probeQuery.isLoading} />
                <Select
                  value={chosen}
                  onValueChange={(v) =>
                    dispatch({ type: "SET_CREDENTIAL", identityKey: id.key, profileName: v })
                  }
                >
                  <SelectTrigger className="w-52 shrink-0" data-testid={`cred-select-${id.key}`}>
                    <SelectValue placeholder="Reuse existing profile…" />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.length === 0 ? (
                      <div className="px-2 py-1.5 text-xs text-muted-foreground">
                        No profiles yet — create one with “+ New”.
                      </div>
                    ) : (
                      profiles.map((p) => (
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
                  onClick={() => setCreateFor(id.key)}
                  className="shrink-0 rounded-md border border-input bg-background px-3 py-1.5 text-xs hover:bg-accent"
                >
                  + New
                </button>
              </div>
              {showPassphrase && (
                <div className="flex items-center gap-2 pl-12">
                  <Input
                    type="password"
                    autoComplete="new-password"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    placeholder="Key passphrase"
                    value={passphrases[id.key] ?? ""}
                    onChange={(e) =>
                      setPassphrases((prev) => ({ ...prev, [id.key]: e.target.value }))
                    }
                    className="h-8 max-w-xs"
                    data-testid={`cred-passphrase-${id.key}`}
                  />
                  <span className="text-xs text-muted-foreground">
                    Encrypted key — saved to your OS keychain, never the inventory file.
                  </span>
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {/* "Create new" reuses the standard dialog — prefilled (Part C) to
          the detected backend + key path + username. It persists the
          profile and enrolls any keyring secret once (Rule 1). On success
          we point this identity at the new profile name. */}
      <AuthProfileDialog
        open={createFor !== null}
        mode="add"
        suggestion={suggestion}
        onOpenChange={(o) => !o && setCreateFor(null)}
        focusSecretValueOnOpen
        onCreated={(name) => {
          if (createFor)
            dispatch({ type: "SET_CREDENTIAL", identityKey: createFor, profileName: name });
          setCreateFor(null);
        }}
      />
    </div>
  );
}

/** Small status pill shown per identity: the probe verdict for a key, or
 *  a plain "agent" tag for ssh_agent logins. Password logins get none. */
function VerdictBadge({
  id,
  verdict,
  pending,
}: {
  id: ImportIdentityMeta;
  verdict: KeyProbeVerdict | undefined;
  pending: boolean;
}) {
  if (id.suggested_backend === "ssh_agent") return <Badge tone="muted">agent</Badge>;
  if (id.suggested_backend !== "ssh_key") return null;
  if (!verdict) return pending ? <Badge tone="muted">checking…</Badge> : null;
  switch (verdict.status) {
    case "unencrypted":
      return <Badge tone="green">key ready</Badge>;
    case "encrypted":
      return <Badge tone="amber">encrypted</Badge>;
    case "unparseable":
      return (
        <Badge tone="red" title={verdict.hint}>
          can’t read key
        </Badge>
      );
    case "unreadable":
      return (
        <Badge tone="amber" title={verdict.detail}>
          not on this machine
        </Badge>
      );
  }
}

function Badge({
  tone,
  title,
  children,
}: {
  tone: "muted" | "green" | "amber" | "red";
  title?: string;
  children: React.ReactNode;
}) {
  const tones: Record<typeof tone, string> = {
    muted: "bg-muted text-muted-foreground",
    green: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
    amber: "bg-amber-500/15 text-amber-700 dark:text-amber-500",
    red: "bg-red-500/15 text-red-700 dark:text-red-400",
  };
  return (
    <span
      className={`shrink-0 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}
      title={title}
    >
      {children}
    </span>
  );
}
