import { useState } from "react";

import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery } from "@tanstack/react-query";
import { FolderTree, Palette, Server, Terminal, type LucideIcon } from "lucide-react";
import { useForm, type FieldErrors } from "react-hook-form";

import { AuthProfileDialog } from "@/components/dialogs/AuthProfileDialog";
import {
  AppearanceFields,
  ConnectionFields,
  DEVICE_SECTIONS,
  OrganizationFields,
  SECTION_FOR_FIELD,
  TerminalFields,
  type DeviceSectionId,
} from "@/components/dialogs/DeviceFormFields";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { listAuthProfiles, type DeviceInput, type DeviceMeta } from "@/lib/api";
import { useExistingGroups } from "@/lib/groups";
import { useUpdateDevice } from "@/lib/mutations";
import { deviceFormSchema, type DeviceFormValues } from "@/lib/schemas";
import { cn } from "@/lib/utils";

export interface EditDeviceDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  device: DeviceMeta;
}

const FORM_ID = "edit-device-form";

/** Left-nav rail icons per section (v4.1.0). */
const SECTION_ICON: Record<DeviceSectionId, LucideIcon> = {
  connection: Server,
  organization: FolderTree,
  appearance: Palette,
  terminal: Terminal,
};

const RAIL_TRIGGER_CLASSES = "w-full justify-start";
const PANE_CLASSES = "mt-0 min-w-0 flex-1 overflow-y-auto pr-1";

/**
 * v4.1.0 — the device settings dialog is a left-nav shell (mirroring
 * `SettingsDialog`): a section rail on the left, the selected section's
 * fields in the pane. The fields themselves are the shared section
 * components from `DeviceFormFields`, unchanged.
 *
 * It is ONE react-hook-form form split across tab panes. Radix Tabs
 * lazy-mounts the inactive panes, but RHF seeds every value via `values`
 * and validates the whole object through the zod resolver, so unmounted
 * sections still submit and validate correctly. A validation error in a
 * non-active section can't hide: `onInvalid` jumps the rail to the first
 * section that has one.
 */
export function EditDeviceDialog({ open, onOpenChange, device }: EditDeviceDialogProps) {
  const [authDialogOpen, setAuthDialogOpen] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [section, setSection] = useState<DeviceSectionId>("connection");

  const authProfiles = useQuery({
    queryKey: ["authProfiles"],
    queryFn: listAuthProfiles,
    enabled: open,
  });
  const existingGroups = useExistingGroups();

  // `values` (RHF source-of-truth) auto-resets the form whenever
  // `device` changes — replaces the old `useEffect(() =>
  // form.reset(...))` pattern. Re-prefills when a different device
  // is selected for editing, no effect required.
  const form = useForm<DeviceFormValues>({
    resolver: zodResolver(deviceFormSchema),
    values: deviceToFormValues(device),
  });

  const updateMutation = useUpdateDevice();

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
      // Match AddDeviceDialog: collapse the unchecked state to `null`
      // so the backend serializes only when the user explicitly opted
      // in. This means turning the checkbox off REMOVES the field.
      syntax_highlighting: values.syntax_highlighting ? true : null,
      quick_copy_paste: values.quick_copy_paste ? true : null,
      // Appearance overrides — the "" / 0 sentinels mean "use the global
      // default", collapsed to null so the TOML stays clean.
      font_family: values.font_family.trim() === "" ? null : values.font_family,
      font_size: values.font_size > 0 ? values.font_size : null,
      bold_color: values.bold_color ? true : null,
      // Not editable here — preserve verbatim. `update_device` is a
      // whole-record replace, so omitting this would silently wipe a
      // weak-crypto opt-in remembered via the WeakCryptoConfirmDialog.
      allow_weak_crypto: device.allow_weak_crypto,
      // Same passthrough: the NetBox sync link (v6.2.0) is machine-managed,
      // not form-edited — dropping it here would orphan the device from
      // every future sync diff.
      netbox_id: device.netbox_id,
      // v6.5.0 — editable here, same collapse discipline as Add.
      jump_via: values.jump_via === "" ? null : values.jump_via,
      forward_agent: values.forward_agent ? true : null,
    };
    updateMutation.mutate(
      { id: device.id, input },
      {
        onSuccess: () => onOpenChange(false),
        onError: (e) => setSubmitError(e instanceof Error ? e.message : String(e)),
      },
    );
  };

  // Reveal a stranded validation error by jumping the rail to the first
  // section (in field order) that owns an errored field.
  const onInvalid = (errors: FieldErrors<DeviceFormValues>) => {
    const first = (Object.keys(SECTION_FOR_FIELD) as (keyof DeviceFormValues)[]).find(
      (f) => errors[f],
    );
    if (first) setSection(SECTION_FOR_FIELD[first]);
  };

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="h-[min(34rem,85vh)] grid-rows-[auto_minmax(0,1fr)_auto] sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit device</DialogTitle>
            <DialogDescription>
              Renaming the ID rewrites it across the inventory. The mutation is atomic.
            </DialogDescription>
          </DialogHeader>

          <Form {...form}>
            <form
              id={FORM_ID}
              onSubmit={form.handleSubmit(onSubmit, onInvalid)}
              className="flex min-h-0 min-w-0"
            >
              <Tabs
                orientation="vertical"
                value={section}
                onValueChange={(v) => setSection(v as DeviceSectionId)}
                className="flex min-h-0 min-w-0 w-full gap-4"
              >
                <TabsList className="h-auto w-40 shrink-0 flex-col items-stretch gap-1 overflow-y-auto">
                  {DEVICE_SECTIONS.map((s) => {
                    const Icon = SECTION_ICON[s.id];
                    return (
                      <TabsTrigger key={s.id} value={s.id} className={RAIL_TRIGGER_CLASSES}>
                        <Icon className="mr-1.5 h-3.5 w-3.5" />
                        {s.label}
                      </TabsTrigger>
                    );
                  })}
                </TabsList>

                <TabsContent value="connection" className={PANE_CLASSES}>
                  <ConnectionFields
                    control={form.control}
                    authProfiles={authProfiles.data ?? []}
                    onCreateAuthProfile={() => setAuthDialogOpen(true)}
                  />
                </TabsContent>
                <TabsContent value="organization" className={PANE_CLASSES}>
                  <OrganizationFields control={form.control} existingGroups={existingGroups} />
                </TabsContent>
                <TabsContent value="appearance" className={PANE_CLASSES}>
                  <AppearanceFields control={form.control} />
                </TabsContent>
                <TabsContent value="terminal" className={PANE_CLASSES}>
                  <TerminalFields control={form.control} />
                </TabsContent>
              </Tabs>
            </form>
          </Form>

          <DialogFooter className={cn(submitError && "flex-col items-stretch gap-2 sm:flex-row")}>
            {submitError && (
              <p className="flex-1 text-sm text-destructive" role="alert">
                {submitError}
              </p>
            )}
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={updateMutation.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" form={FORM_ID} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? "Saving..." : "Save"}
            </Button>
          </DialogFooter>
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

function deviceToFormValues(d: DeviceMeta): DeviceFormValues {
  return {
    id: d.id,
    host: d.host,
    port: d.port,
    vendor: (d.vendor as DeviceFormValues["vendor"]) ?? "unknown",
    group: d.group ?? "",
    color: d.color ?? "",
    tags: d.tags,
    auth: d.auth,
    // null/missing in TOML → unchecked.
    syntax_highlighting: d.syntax_highlighting === true,
    quick_copy_paste: d.quick_copy_paste === true,
    // "" / 0 = "use the global default".
    font_family: d.font_family ?? "",
    font_size: d.font_size ?? 0,
    bold_color: d.bold_color === true,
    // "" = direct; null/missing forward_agent → unchecked (v6.5.0).
    jump_via: d.jump_via ?? "",
    forward_agent: d.forward_agent === true,
  };
}
