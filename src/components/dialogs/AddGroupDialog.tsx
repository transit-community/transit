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
import { useAddGroup } from "@/lib/mutations";
import { addGroupFormSchema, type AddGroupFormValues } from "@/lib/schemas";

export interface AddGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** When set (the "New subgroup..." entry point), the path field is
   *  prefilled with `<parent>/` so the user just types the leaf name.
   *  Undefined = a top-level group. */
  defaultParent?: string;
}

export function AddGroupDialog({ open, onOpenChange, defaultParent }: AddGroupDialogProps) {
  const [submitError, setSubmitError] = useState<string | null>(null);
  const prefill = defaultParent ? `${defaultParent}/` : "";
  const form = useForm<AddGroupFormValues>({
    resolver: zodResolver(addGroupFormSchema),
    defaultValues: { path: prefill },
  });

  // Sync the prefilled path when the dialog (re)opens against a parent.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    if (open) {
      form.reset({ path: prefill });
      setSubmitError(null);
    }
  }, [open, prefill, form]);

  const addMutation = useAddGroup();

  const onSubmit = (values: AddGroupFormValues) => {
    setSubmitError(null);
    addMutation.mutate(values.path, {
      onSuccess: () => onOpenChange(false),
      onError: (e) => setSubmitError(e instanceof Error ? e.message : String(e)),
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{defaultParent ? "New subgroup" : "New group"}</DialogTitle>
          <DialogDescription>
            Create an empty group. It appears in the sidebar immediately; drag connections into it
            or add a device with this group.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="grid gap-4">
            <FormField
              control={form.control}
              name="path"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Group path</FormLabel>
                  <FormControl>
                    <Input
                      autoComplete="off"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      placeholder="e.g. Lab/Junos"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    Use <code>/</code> to nest (e.g. <code>Lab/Junos</code>).
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
                disabled={addMutation.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={addMutation.isPending}>
                {addMutation.isPending ? "Creating..." : "Create"}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
