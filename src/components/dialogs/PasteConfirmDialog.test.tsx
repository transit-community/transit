import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { PasteConfirmDialog } from "@/components/dialogs/PasteConfirmDialog";

/**
 * Stateful harness mirroring TerminalPane's wiring: `open` is real state so
 * Radix dismissal (Escape with the find row closed) actually closes the
 * dialog, and onConfirm closes it like confirmPaste does.
 */
function Harness({
  text,
  onConfirm = vi.fn(),
  onOpenChange = vi.fn(),
}: {
  text: string;
  onConfirm?: (draft: string) => void;
  onOpenChange?: (open: boolean) => void;
}) {
  const [open, setOpen] = useState(true);
  return (
    <PasteConfirmDialog
      open={open}
      text={text}
      onOpenChange={(o) => {
        onOpenChange(o);
        setOpen(o);
      }}
      onConfirm={(draft) => {
        onConfirm(draft);
        setOpen(false);
      }}
      onCloseAutoFocus={(e) => e.preventDefault()}
    />
  );
}

const textarea = () => screen.getByTestId("paste-edit-textarea") as HTMLTextAreaElement;
const findInput = () => screen.getByTestId("paste-find-input") as HTMLInputElement;
const counter = () => screen.getByTestId("paste-find-counter");

async function openFindRow() {
  await userEvent.click(screen.getByTestId("paste-find-toggle"));
}

describe("PasteConfirmDialog", () => {
  it("renders the title, line count, and initial text", () => {
    render(<Harness text={"line1\nline2\nline3"} />);
    expect(screen.getByText(/paste multi-line content/i)).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(textarea().value).toBe("line1\nline2\nline3");
  });

  it("hides the find row by default; the toggle opens it and focuses the find input", async () => {
    render(<Harness text={"a\nb"} />);
    expect(screen.queryByTestId("paste-find-input")).not.toBeInTheDocument();
    await openFindRow();
    expect(findInput()).toBeInTheDocument();
    expect(findInput()).toHaveFocus();
  });

  it("Cmd+F and Ctrl+F open the find row; combined or shifted modifiers do not", () => {
    render(<Harness text={"a\nb"} />);
    const dialog = screen.getByRole("alertdialog");

    // meta+ctrl together violates the XOR accelerator convention.
    fireEvent.keyDown(dialog, { key: "f", metaKey: true, ctrlKey: true });
    expect(screen.queryByTestId("paste-find-input")).not.toBeInTheDocument();
    // a stray Shift must not count either (hotkeys.ts isAccel).
    fireEvent.keyDown(dialog, { key: "f", metaKey: true, shiftKey: true });
    expect(screen.queryByTestId("paste-find-input")).not.toBeInTheDocument();

    fireEvent.keyDown(dialog, { key: "f", metaKey: true });
    expect(screen.getByTestId("paste-find-input")).toBeInTheDocument();
  });

  it("Ctrl+F (non-mac accelerator) opens the find row too", () => {
    render(<Harness text={"a\nb"} />);
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "f", ctrlKey: true });
    expect(screen.getByTestId("paste-find-input")).toBeInTheDocument();
  });

  it("shows a live match counter: n of N, No matches, empty when the query is empty", async () => {
    render(<Harness text={"line1\nline2\nline3"} />);
    await openFindRow();
    expect(counter().textContent).toBe("");

    await userEvent.type(findInput(), "line");
    expect(counter().textContent).toBe("1 of 3");

    await userEvent.clear(findInput());
    await userEvent.type(findInput(), "zzz");
    expect(counter().textContent).toBe("No matches");

    await userEvent.clear(findInput());
    expect(counter().textContent).toBe("");
  });

  it("Enter reveals the current match first, then advances; Shift+Enter and F3 navigate", async () => {
    render(<Harness text={"line1\nline2\nline3"} />);
    await openFindRow();
    await userEvent.type(findInput(), "line");
    expect(counter().textContent).toBe("1 of 3");

    // First Enter reveals match 1 (no select-while-typing) — it must not skip to 2.
    fireEvent.keyDown(findInput(), { key: "Enter" });
    expect(counter().textContent).toBe("1 of 3");
    expect(textarea().selectionStart).toBe(0);
    expect(textarea().selectionEnd).toBe(4);

    fireEvent.keyDown(findInput(), { key: "Enter" });
    expect(counter().textContent).toBe("2 of 3");
    expect(textarea().selectionStart).toBe(6);

    fireEvent.keyDown(findInput(), { key: "Enter", shiftKey: true });
    expect(counter().textContent).toBe("1 of 3");

    // F3 works from anywhere in the dialog (handled at content level).
    fireEvent.keyDown(findInput(), { key: "F3" });
    expect(counter().textContent).toBe("2 of 3");
    fireEvent.keyDown(textarea(), { key: "F3", shiftKey: true });
    expect(counter().textContent).toBe("1 of 3");
  });

  it("navigation wraps past the last match", async () => {
    render(<Harness text={"aa aa"} />);
    await openFindRow();
    await userEvent.type(findInput(), "aa");
    fireEvent.keyDown(findInput(), { key: "Enter" }); // reveal 1
    fireEvent.keyDown(findInput(), { key: "Enter" }); // 2
    fireEvent.keyDown(findInput(), { key: "Enter" }); // wrap → 1
    expect(counter().textContent).toBe("1 of 2");
  });

  it("Match case narrows the match set and flips aria-pressed", async () => {
    render(<Harness text={"Interface up\ninterface down"} />);
    await openFindRow();
    await userEvent.type(findInput(), "interface");
    expect(counter().textContent).toBe("1 of 2");

    const toggle = screen.getByTestId("paste-find-case");
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(counter().textContent).toBe("1 of 1");
  });

  it("Whole word narrows the match set", async () => {
    render(<Harness text={"ge-0/0/1 gear"} />);
    await openFindRow();
    await userEvent.type(findInput(), "ge");
    expect(counter().textContent).toBe("1 of 2");
    await userEvent.click(screen.getByTestId("paste-find-word"));
    expect(counter().textContent).toBe("1 of 1");
  });

  it("Replace substitutes only the current match and re-anchors to the next", async () => {
    render(<Harness text={"aaa bbb aaa"} />);
    await openFindRow();
    await userEvent.type(findInput(), "aaa");
    await userEvent.type(screen.getByTestId("paste-replace-input"), "xxx");
    await userEvent.click(screen.getByTestId("paste-replace-one"));

    expect(textarea().value).toBe("xxx bbb aaa");
    expect(counter().textContent).toBe("1 of 1");
    expect(screen.getByTestId("paste-undo")).toBeInTheDocument();
  });

  it("Enter in the replace input replaces the current match and never confirms", async () => {
    const onConfirm = vi.fn();
    render(<Harness text={"aaa bbb aaa"} onConfirm={onConfirm} />);
    await openFindRow();
    await userEvent.type(findInput(), "aaa");
    const replaceInput = screen.getByTestId("paste-replace-input");
    await userEvent.type(replaceInput, "yyy");
    fireEvent.keyDown(replaceInput, { key: "Enter" });

    expect(textarea().value).toBe("yyy bbb aaa");
    expect(onConfirm).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("Replace all substitutes every match and reports No matches", async () => {
    render(<Harness text={"vlan 10\nvlan 10\ndescription ten"} />);
    await openFindRow();
    await userEvent.type(findInput(), "vlan 10");
    expect(counter().textContent).toBe("1 of 2");
    await userEvent.type(screen.getByTestId("paste-replace-input"), "vlan 20");
    await userEvent.click(screen.getByTestId("paste-replace-all"));

    expect(textarea().value).toBe("vlan 20\nvlan 20\ndescription ten");
    expect(counter().textContent).toBe("No matches");
  });

  it("Undo restores the exact prior text and disappears when the stack drains", async () => {
    render(<Harness text={"one two one"} />);
    await openFindRow();
    await userEvent.type(findInput(), "one");
    await userEvent.type(screen.getByTestId("paste-replace-input"), "three");
    await userEvent.click(screen.getByTestId("paste-replace-all"));
    expect(textarea().value).toBe("three two three");

    await userEvent.click(screen.getByTestId("paste-undo"));
    expect(textarea().value).toBe("one two one");
    expect(counter().textContent).toBe("1 of 2");
    expect(screen.queryByTestId("paste-undo")).not.toBeInTheDocument();
  });

  it("Enter in the find input never confirms or closes the dialog", async () => {
    const onConfirm = vi.fn();
    const onOpenChange = vi.fn();
    render(<Harness text={"a\nb"} onConfirm={onConfirm} onOpenChange={onOpenChange} />);
    await openFindRow();
    await userEvent.type(findInput(), "a");
    fireEvent.keyDown(findInput(), { key: "Enter" });
    fireEvent.keyDown(findInput(), { key: "Enter" });

    expect(onConfirm).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("Escape closes the find row first, the dialog second", async () => {
    const onOpenChange = vi.fn();
    render(<Harness text={"a\nb"} onOpenChange={onOpenChange} />);
    await openFindRow();
    expect(findInput()).toHaveFocus();

    await userEvent.keyboard("{Escape}");
    // Row gone, dialog intact — Radix dismissal was preventDefaulted.
    expect(screen.queryByTestId("paste-find-input")).not.toBeInTheDocument();
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
    expect(onOpenChange).not.toHaveBeenCalled();

    await userEvent.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("closing the find row returns focus to the textarea", async () => {
    render(<Harness text={"a\nb"} />);
    await openFindRow();
    await userEvent.click(screen.getByTestId("paste-find-close"));
    expect(screen.queryByTestId("paste-find-input")).not.toBeInTheDocument();
    expect(textarea()).toHaveFocus();
  });

  it("prefills the query from a single-line textarea selection", async () => {
    render(<Harness text={"show interfaces terse"} />);
    act(() => {
      textarea().focus();
      textarea().setSelectionRange(5, 15);
    });
    await openFindRow();
    expect(findInput().value).toBe("interfaces");
    expect(counter().textContent).toBe("1 of 1");
  });

  it("emptying the textarea disables Paste", async () => {
    render(<Harness text={"a\nb"} />);
    fireEvent.change(textarea(), { target: { value: "" } });
    expect(screen.getByRole("button", { name: /^paste$/i })).toBeDisabled();
  });

  it("Paste hands onConfirm the edited draft, not the original text", async () => {
    const onConfirm = vi.fn();
    render(<Harness text={"user admin secret1\nuser operator secret1"} onConfirm={onConfirm} />);
    await openFindRow();
    await userEvent.type(findInput(), "secret1");
    await userEvent.type(screen.getByTestId("paste-replace-input"), "REDACTED");
    await userEvent.click(screen.getByTestId("paste-replace-all"));
    await userEvent.click(screen.getByRole("button", { name: /^paste$/i }));

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledWith("user admin REDACTED\nuser operator REDACTED");
  });

  it("re-seeds the draft and resets find/undo state on every reopen — including same text", async () => {
    const noop = () => undefined;
    const { rerender } = render(
      <PasteConfirmDialog
        open
        text={"one\ntwo"}
        onOpenChange={noop}
        onConfirm={noop}
        onCloseAutoFocus={(e) => e.preventDefault()}
      />,
    );
    await openFindRow();
    await userEvent.type(findInput(), "one");
    await userEvent.type(screen.getByTestId("paste-replace-input"), "three");
    await userEvent.click(screen.getByTestId("paste-replace-all"));
    fireEvent.change(textarea(), { target: { value: "hand edited" } });

    const close = (
      <PasteConfirmDialog
        open={false}
        text={"one\ntwo"}
        onOpenChange={noop}
        onConfirm={noop}
        onCloseAutoFocus={(e) => e.preventDefault()}
      />
    );
    rerender(close);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();

    // Reopen with DIFFERENT text: everything re-seeds.
    rerender(
      <PasteConfirmDialog
        open
        text={"alpha\nbeta"}
        onOpenChange={noop}
        onConfirm={noop}
        onCloseAutoFocus={(e) => e.preventDefault()}
      />,
    );
    expect(textarea().value).toBe("alpha\nbeta");
    expect(screen.queryByTestId("paste-find-input")).not.toBeInTheDocument();
    expect(screen.queryByTestId("paste-undo")).not.toBeInTheDocument();

    // Edit, close, reopen with the SAME text: the draft still re-seeds
    // (the reset keys on the open transition, not on text identity).
    fireEvent.change(textarea(), { target: { value: "scribbles" } });
    rerender(close);
    rerender(
      <PasteConfirmDialog
        open
        text={"one\ntwo"}
        onOpenChange={noop}
        onConfirm={noop}
        onCloseAutoFocus={(e) => e.preventDefault()}
      />,
    );
    expect(textarea().value).toBe("one\ntwo");
  });
});
