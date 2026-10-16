import { useEffect, useState } from "react";

import { zodResolver } from "@hookform/resolvers/zod";
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
import { useRenameGroup } from "@/lib/mutations";
import { renameGroupFormSchema, type RenameGroupFormValues } from "@/lib/schemas";

export interface RenameGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The current group path being renamed (e.g. "Lab/Junos"). */
  oldPath: string;
}

export function RenameGroupDialog({ open, onOpenChange, oldPath }: RenameGroupDialogProps) {
  const [submitError, setSubmitError] = useState<string | null>(null);
  const form = useForm<RenameGroupFormValues>({
    resolver: zodResolver(renameGroupFormSchema),
    defaultValues: { newPath: oldPath },
  });

  // Canonical RHF + Radix Dialog pattern: when `open` flips true,
  // sync the form to the latest `oldPath` and clear any prior error.
  // The trigger is a *prop change*, not a user event — react-doctor's
  // event-handler rule doesn't fit here, so it's disabled with intent.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (open) {
      form.reset({ newPath: oldPath });
      setSubmitError(null);
    }
  }, [open, oldPath, form]);

  const renameMutation = useRenameGroup();

  const onSubmit = (values: RenameGroupFormValues) => {
    setSubmitError(null);
    renameMutation.mutate(
      { oldPath, newPath: values.newPath },
      {
        onSuccess: () => onOpenChange(false),
        onError: (e) => setSubmitError(e instanceof Error ? e.message : String(e)),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Rename group</DialogTitle>
          <DialogDescription>
            Renaming <span className="font-mono">{oldPath}</span> updates every device whose group
            equals or starts with this path. Renaming into an existing group merges the devices.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="grid gap-4">
            <FormField
              control={form.control}
              name="newPath"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>New path</FormLabel>
                  <FormControl>
                    <Input
                      autoComplete="off"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    Use <code>/</code> to nest. Leave blank — never; use Edit Device to ungroup
                    individual devices instead.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
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
                disabled={renameMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={renameMutation.isPending}>
                {renameMutation.isPending ? "Renaming..." : "Rename"}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
