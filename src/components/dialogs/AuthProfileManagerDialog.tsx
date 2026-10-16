import { useState } from "react";

import { useQuery } from "@tanstack/react-query";
import { AlertCircle, KeyRound, Pencil, Plus, Trash2 } from "lucide-react";

import { AuthProfileDialog } from "@/components/dialogs/AuthProfileDialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { type AuthProfileMeta, listAuthProfiles, listDevices, testSecretResolve } from "@/lib/api";
import { useDeleteAuthProfile } from "@/lib/mutations";

interface AuthProfileManagerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type InnerDialog =
  | { kind: "closed" }
  | { kind: "add" }
  | { kind: "edit"; profile: AuthProfileMeta; focusSecret?: boolean };

/**
 * Standalone auth profile manager — fills the C1 gap where the
 * existing `AuthProfileDialog` is only reachable from inside
 * `AddDeviceDialog` / `EditDeviceDialog`.
 *
 * Lists every profile, with a "Used by N devices" badge derived
 * client-side from the existing `listDevices()` query (no new IPC).
 * Edit reuses `AuthProfileDialog` in update mode with username +
 * backend kind prefilled from `AuthProfileMeta`. Delete is gated
 * by usage: blocked with the dependent-device list when in-use,
 * confirms via `AlertDialog` when not.
 *
 * The backend's `mutator::delete_auth_profile` enforces the same
 * "in use" guard structurally; the client pre-check exists for
 * UX (avoid the round-trip + parse-the-error dance for the common
 * case).
 */
export function AuthProfileManagerDialog({ open, onOpenChange }: AuthProfileManagerDialogProps) {
  const profilesQuery = useQuery({ queryKey: ["authProfiles"], queryFn: listAuthProfiles });
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  const deleteMutation = useDeleteAuthProfile();

  const [innerDialog, setInnerDialog] = useState<InnerDialog>({ kind: "closed" });
  const [deleteTarget, setDeleteTarget] = useState<AuthProfileMeta | null>(null);
  const [blockingUsage, setBlockingUsage] = useState<string[] | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const usingDevices = (profileName: string): string[] =>
    (devicesQuery.data ?? []).filter((d) => d.auth === profileName).map((d) => d.id);

  function handleDeleteClick(profile: AuthProfileMeta) {
    const inUse = usingDevices(profile.name);
    setDeleteError(null);
    if (inUse.length > 0) {
      setBlockingUsage(inUse);
      setDeleteTarget(profile);
    } else {
      setBlockingUsage(null);
      setDeleteTarget(profile);
    }
  }

  function confirmDelete() {
    if (!deleteTarget) return;
    deleteMutation.mutate(deleteTarget.name, {
      onSuccess: () => {
        setDeleteTarget(null);
        setBlockingUsage(null);
        setDeleteError(null);
      },
      onError: (e) => {
        // Defense in depth: backend's AuthProfileInUse should be
        // caught by the pre-check above, but a TOCTOU between
        // pre-check and IPC is possible (user added a device that
        // references this profile in another window between our
        // query refetch and the delete call). Surface the raw
        // message in that rare case.
        setDeleteError(e instanceof Error ? e.message : String(e));
      },
    });
  }

  function closeDeleteAlert() {
    setDeleteTarget(null);
    setBlockingUsage(null);
    setDeleteError(null);
  }

  const profiles = profilesQuery.data ?? [];
  const isEmpty = !profilesQuery.isLoading && profiles.length === 0;

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-muted-foreground" />
              Auth profiles
            </DialogTitle>
            <DialogDescription>
              Profiles are inventory references; the actual secret lives in its backend (OS
              keychain, SSH agent, 1Password, etc.) and never enters the inventory file.
            </DialogDescription>
          </DialogHeader>

          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {profiles.length} {profiles.length === 1 ? "profile" : "profiles"}
            </p>
            <Button
              type="button"
              size="sm"
              onClick={() => setInnerDialog({ kind: "add" })}
              data-testid="auth-profile-add"
            >
              <Plus className="mr-1 h-3.5 w-3.5" />
              New profile
            </Button>
          </div>

          {profilesQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Loading profiles...</p>
          ) : isEmpty ? (
            <EmptyState onAdd={() => setInnerDialog({ kind: "add" })} />
          ) : (
            <ScrollArea className="max-h-[60vh]">
              <ul className="divide-y divide-border" data-testid="auth-profile-list">
                {profiles.map((profile) => (
                  <ProfileRow
                    key={profile.name}
                    profile={profile}
                    usingDevices={usingDevices(profile.name)}
                    onEdit={() => setInnerDialog({ kind: "edit", profile })}
                    onDelete={() => handleDeleteClick(profile)}
                    onSetValue={() => setInnerDialog({ kind: "edit", profile, focusSecret: true })}
                  />
                ))}
              </ul>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>

      {/* Stacked AuthProfileDialog for add/edit. Rendered outside the
          parent <Dialog> so Radix's z-index stacking puts it above the
          Manager. */}
      {innerDialog.kind !== "closed" && (
        <AuthProfileDialog
          open
          onOpenChange={(o) => {
            if (!o) setInnerDialog({ kind: "closed" });
          }}
          mode={innerDialog.kind}
          existingName={innerDialog.kind === "edit" ? innerDialog.profile.name : undefined}
          existingMeta={
            innerDialog.kind === "edit"
              ? {
                  username: innerDialog.profile.username,
                  backend: innerDialog.profile.backend,
                  key_path: innerDialog.profile.key_path,
                }
              : undefined
          }
          focusSecretValueOnOpen={innerDialog.kind === "edit" && innerDialog.focusSecret === true}
        />
      )}

      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(o) => {
          if (!o) closeDeleteAlert();
        }}
      >
        <AlertDialogContent data-testid="auth-profile-delete-alert">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {blockingUsage && blockingUsage.length > 0
                ? `Can't delete ${deleteTarget?.name ?? ""}`
                : `Delete ${deleteTarget?.name ?? ""}?`}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              {blockingUsage && blockingUsage.length > 0 ? (
                <div className="space-y-2">
                  <p>
                    {blockingUsage.length}{" "}
                    {blockingUsage.length === 1 ? "device references" : "devices reference"} this
                    profile:
                  </p>
                  <ul className="rounded border bg-muted/30 px-3 py-2 font-mono text-xs">
                    {blockingUsage.map((id) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                  <p>
                    Reassign {blockingUsage.length === 1 ? "that device" : "those devices"} to a
                    different profile before deleting.
                  </p>
                </div>
              ) : (
                <p>
                  The profile will be removed from the inventory. The secret in its backend
                  (keychain entry, agent identity, etc.) is unaffected.
                </p>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>

          {deleteError && (
            <div
              className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
              role="alert"
            >
              {deleteError}
            </div>
          )}

          <AlertDialogFooter>
            <AlertDialogCancel onClick={closeDeleteAlert}>
              {blockingUsage && blockingUsage.length > 0 ? "Close" : "Cancel"}
            </AlertDialogCancel>
            {(!blockingUsage || blockingUsage.length === 0) && (
              <AlertDialogAction
                onClick={(e) => {
                  e.preventDefault();
                  confirmDelete();
                }}
                disabled={deleteMutation.isPending}
                data-testid="auth-profile-delete-confirm"
              >
                {deleteMutation.isPending ? "Deleting..." : "Delete"}
              </AlertDialogAction>
            )}
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

interface ProfileRowProps {
  profile: AuthProfileMeta;
  usingDevices: string[];
  onEdit: () => void;
  onDelete: () => void;
  onSetValue: () => void;
}

function ProfileRow({ profile, usingDevices, onEdit, onDelete, onSetValue }: ProfileRowProps) {
  const [expanded, setExpanded] = useState(false);
  const usageCount = usingDevices.length;
  const hasUsage = usageCount > 0;

  // Phase 7a C14 — for keyring profiles only, probe the OS keystore
  // to find out whether the secret has been enrolled. Backend
  // returns `{ length }` on hit and rejects on miss; we don't care
  // about the value, just whether the lookup succeeds. The query
  // is invalidated automatically by `useEnrollSecret`'s onSuccess.
  const enrollmentQuery = useQuery({
    queryKey: ["authProfileEnrolled", profile.name],
    queryFn: () => testSecretResolve(profile.name),
    enabled: profile.backend === "keyring",
    retry: false,
    staleTime: 30_000,
  });
  const notEnrolled =
    profile.backend === "keyring" && !enrollmentQuery.isLoading && enrollmentQuery.isError;

  return (
    <li className="py-2.5" data-testid={`auth-profile-row-${profile.name}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium">{profile.name}</span>
            <Badge variant="secondary" className="text-[10px]">
              {profile.backend}
            </Badge>
            {notEnrolled && (
              <button
                type="button"
                onClick={onSetValue}
                className="flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-700 hover:bg-amber-500/20 dark:text-amber-400"
                data-testid={`auth-profile-not-enrolled-${profile.name}`}
                title="Click to set the secret value"
              >
                <AlertCircle className="h-3 w-3" />
                Secret not enrolled · Set value
              </button>
            )}
            {hasUsage ? (
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                className="rounded-md px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-accent"
                data-testid={`auth-profile-usage-${profile.name}`}
              >
                Used by {usageCount}
              </button>
            ) : (
              <span className="text-[10px] text-muted-foreground">Unused</span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">{profile.username}</p>
          {expanded && hasUsage && (
            <ul
              className="mt-1.5 rounded border bg-muted/30 px-2 py-1 font-mono text-[11px]"
              data-testid={`auth-profile-usage-list-${profile.name}`}
            >
              {usingDevices.map((id) => (
                <li key={id}>{id}</li>
              ))}
            </ul>
          )}
        </div>

        <div className="flex shrink-0 gap-1">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={onEdit}
            aria-label={`Edit ${profile.name}`}
            data-testid={`auth-profile-edit-${profile.name}`}
          >
            <Pencil className="h-3.5 w-3.5" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={onDelete}
            aria-label={`Delete ${profile.name}`}
            data-testid={`auth-profile-delete-${profile.name}`}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </li>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-10 text-center">
      <KeyRound className="h-8 w-8 text-muted-foreground" />
      <div>
        <p className="text-sm font-medium">No auth profiles yet</p>
        <p className="text-xs text-muted-foreground">
          Create a profile so devices can reference it for SSH credentials.
        </p>
      </div>
      <Button type="button" onClick={onAdd}>
        <Plus className="mr-1 h-3.5 w-3.5" />
        New profile
      </Button>
    </div>
  );
}
