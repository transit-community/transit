import { useEffect, useState } from "react";

import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";

import { AuthProfileDialog } from "@/components/dialogs/AuthProfileDialog";
import { DeviceFormFields } from "@/components/dialogs/DeviceFormFields";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Form } from "@/components/ui/form";
import { useExistingGroups } from "@/lib/groups";
import { listAuthProfiles, type DeviceInput } from "@/lib/api";
import { useAddDevice } from "@/lib/mutations";
import { deviceFormSchema, type DeviceFormValues } from "@/lib/schemas";

export interface AddDeviceDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Optional pre-fill (e.g. when entering via "New device in this group"). */
  defaultGroup?: string;
}

/** Clean form state for a fresh "New device", optionally pre-filling the
 *  group (the "New device in this group" entry point). */
function buildDefaults(defaultGroup?: string): DeviceFormValues {
  return {
    id: "",
    host: "",
    port: 22,
    vendor: "junos",
    group: defaultGroup ?? "",
    color: "",
    tags: [],
    auth: "",
    syntax_highlighting: false,
    quick_copy_paste: false,
    // "" / 0 / false = "use the global default" (collapsed to null on submit).
    font_family: "",
    font_size: 0,
    bold_color: false,
    // "" = direct connection; false = no agent forwarding (v6.5.0).
    jump_via: "",
    forward_agent: false,
  };
}

export function AddDeviceDialog({ open, onOpenChange, defaultGroup }: AddDeviceDialogProps) {
  const [authDialogOpen, setAuthDialogOpen] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const authProfiles = useQuery({
    queryKey: ["authProfiles"],
    queryFn: listAuthProfiles,
    enabled: open,
  });
  const existingGroups = useExistingGroups();

  const form = useForm<DeviceFormValues>({
    resolver: zodResolver(deviceFormSchema),
    defaultValues: buildDefaults(defaultGroup),
  });

  // `useForm` reads `defaultValues` only once at mount, but Sidebar keeps
  // this dialog mounted and just toggles `open` — so a later "New device
  // in this group" never reached the form (the bug: group not pre-filled).
  // Reset on each open so the group pre-fills every time and every fresh
  // open starts from clean fields.
  useEffect(() => {
    if (open) form.reset(buildDefaults(defaultGroup));
  }, [open, defaultGroup, form]);

  const addMutation = useAddDevice();

  const onSubmit = (values: DeviceFormValues) => {
    setSubmitError(null);
    const input: DeviceInput = {
      id: values.id,
      host: values.host,
      port: values.port,
      vendor: values.vendor,
      group: values.group.trim() === "" ? null : values.group.trim(),
      color: values.color === "" ? null : values.color,
      tags: values.tags,
      auth: values.auth,
      // Send `null` instead of `false` for the unset state so the
      // backend keeps the TOML clean — `syntax_highlighting = false`
      // would only ship if the user explicitly opted out.
      syntax_highlighting: values.syntax_highlighting ? true : null,
      quick_copy_paste: values.quick_copy_paste ? true : null,
      font_family: values.font_family.trim() === "" ? null : values.font_family,
      font_size: values.font_size > 0 ? values.font_size : null,
      bold_color: values.bold_color ? true : null,
      // v6.5.0 — same collapse discipline: "" → null (direct), false →
      // null (no forwarding) so untouched devices stay clean in TOML.
      jump_via: values.jump_via === "" ? null : values.jump_via,
      forward_agent: values.forward_agent ? true : null,
    };
    addMutation.mutate(input, {
      onSuccess: () => {
        form.reset();
        onOpenChange(false);
      },
      onError: (e) => setSubmitError(e instanceof Error ? e.message : String(e)),
    });
  };

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New device</DialogTitle>
            <DialogDescription>
              Add a host to your inventory. Auth profiles are referenced by name — the credential
              itself is fetched from the chosen backend at connect time.
            </DialogDescription>
          </DialogHeader>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="grid gap-4">
              <DeviceFormFields
                control={form.control}
                authProfiles={authProfiles.data ?? []}
                existingGroups={existingGroups}
                onCreateAuthProfile={() => setAuthDialogOpen(true)}
              />
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
                  disabled={addMutation.isPending}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={addMutation.isPending}>
                  {addMutation.isPending ? "Saving..." : "Save"}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      <AuthProfileDialog
        open={authDialogOpen}
        onOpenChange={setAuthDialogOpen}
        mode="add"
        onCreated={(name) => {
          form.setValue("auth", name, { shouldValidate: true });
          setAuthDialogOpen(false);
        }}
      />
    </>
  );
}
