import { CaseSensitive, ChevronDown, ChevronUp, Search, Undo2, WholeWord, X } from "lucide-react";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

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
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { isAccel } from "@/lib/hotkeys";
import { cn } from "@/lib/utils";
import {
  findMatches,
  type MatchRange,
  nextMatchIndex,
  replaceAllMatches,
  replaceRange,
} from "@/lib/terminal/pasteEdit";

/**
 * Multi-line paste confirmation dialog (extracted from TerminalPane in
 * v2.6.3, when Find & Replace grew it past inline size).
 *
 * The security property is unchanged from the inline original: the textarea
 * is the staging area and `onConfirm` hands back exactly its current
 * contents — every find/replace operation only mutates the staged draft the
 * user is looking at ("what you paste is exactly what's sent", §17).
 *
 * Find & Replace is literal-only (no regex mode — deliberate; see
 * lib/terminal/pasteEdit.ts). Replace / Replace all snapshot the prior text
 * onto an explicit Undo stack because a programmatic value swap invalidates
 * the browser's native textarea undo (and Cmd+Z behavior after that differs
 * between WKWebView and WebView2).
 */
export interface PasteConfirmDialogProps {
  /** Controls the Radix open state; TerminalPane passes `pendingPaste !== null`. */
  open: boolean;
  /** Initial textarea content, re-read on every closed→open transition. */
  text: string;
  /** Radix onOpenChange passthrough (Escape with the find row closed, click-out). */
  onOpenChange: (open: boolean) => void;
  /** Paste clicked. Receives the CURRENT draft, find/replace edits included. */
  onConfirm: (draft: string) => void;
  /**
   * Forwarded to AlertDialogContent — the §17 load-bearing focus return
   * (preventDefault + refocus the terminal) stays owned by TerminalPane.
   */
  onCloseAutoFocus: (event: Event) => void;
}

/** Max Replace/Replace-all snapshots kept for Undo (bounds multi-MB pastes). */
const UNDO_LIMIT = 20;

interface ScrollTarget extends MatchRange {
  /** Monotonic nonce so re-navigating to the same range re-fires the effect. */
  seq: number;
}

export function PasteConfirmDialog({
  open,
  text,
  onOpenChange,
  onConfirm,
  onCloseAutoFocus,
}: PasteConfirmDialogProps) {
  const [draft, setDraft] = useState(text);
  const [findOpen, setFindOpen] = useState(false);
  // Escape reaches us through Radix's document-level keydown listener
  // (dismissable-layer wraps it in useEffectEvent — native on React 19.2),
  // which can invoke a STALE onEscapeKeyDown closure: reproduced under
  // happy-dom, the handler saw findOpen=false while the row was open, so
  // Escape killed the whole dialog instead of the row. A ref is identity-
  // stable across renders, so even a stale closure reads the live value.
  const findOpenRef = useRef(findOpen);
  findOpenRef.current = findOpen;
  const [query, setQuery] = useState("");
  const [replacement, setReplacement] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [wholeWord, setWholeWord] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  // Typing shows the live count but never scrolls; the FIRST navigation
  // (Enter / arrows / F3) reveals the current match, and only subsequent
  // ones advance — otherwise match 1 would be skipped without ever being
  // seen (we don't select-while-typing the way browsers do).
  const [navigated, setNavigated] = useState(false);
  const [undoStack, setUndoStack] = useState<string[]>([]);
  const [scrollTarget, setScrollTarget] = useState<ScrollTarget | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const findInputRef = useRef<HTMLInputElement | null>(null);
  const seqRef = useRef(0);

  // Re-seed the draft and reset all find/undo state on every closed→open
  // transition (render-phase adjustment, not an effect: an effect runs
  // post-paint, so production would flash one frame of the PREVIOUS paste's
  // draft — and act() would hide that from tests). Keyed on the transition,
  // not on `text`, so pasting identical clipboard twice still re-seeds; and
  // nothing resets on close, so the exit animation never shows a blanked
  // dialog.
  const [prevOpen, setPrevOpen] = useState(false);
  if (open !== prevOpen) {
    setPrevOpen(open);
    if (open) {
      setDraft(text);
      setFindOpen(false);
      setQuery("");
      setReplacement("");
      setCaseSensitive(false);
      setWholeWord(false);
      setActiveIndex(0);
      setNavigated(false);
      setUndoStack([]);
      setScrollTarget(null);
    }
  }

  const matches = useMemo(
    () => findMatches(draft, query, { caseSensitive, wholeWord }),
    [draft, query, caseSensitive, wholeWord],
  );
  // -1 = no matches; otherwise clamped when the set shrinks under the index.
  const clampedIndex = matches.length === 0 ? -1 : Math.min(activeIndex, matches.length - 1);

  // Focus the find input when the row opens. Deliberately does NOT run on
  // mount (findOpen starts false), so Radix's default focus on Cancel — a
  // blind Enter cancels rather than pastes — is preserved.
  useEffect(() => {
    if (findOpen) {
      findInputRef.current?.focus();
      findInputRef.current?.select();
    }
  }, [findOpen]);

  // Reveal the current match: best-effort selection (engines differ on
  // showing an unfocused selection — the "n of N" counter is the definitive
  // indicator) plus scroll math that must never throw where layout metrics
  // are missing (happy-dom tests: no layout, canvas getContext → null/throw).
  useLayoutEffect(() => {
    const ta = textareaRef.current;
    if (!scrollTarget || !ta) return;
    try {
      ta.setSelectionRange(scrollTarget.start, scrollTarget.end);
    } catch {
      // best-effort
    }
    const before = ta.value.slice(0, scrollTarget.start);
    // Same CRLF/CR/LF convention as the dialog's line counter.
    const line = before.split(/\r\n|\r|\n/).length - 1;
    let lineHeight = Number.parseFloat(getComputedStyle(ta).lineHeight);
    if (!Number.isFinite(lineHeight) || lineHeight <= 0) lineHeight = 16;
    const viewH = ta.clientHeight || 0;
    ta.scrollTop = Math.max(0, line * lineHeight - Math.max(0, viewH / 2 - lineHeight / 2));
    try {
      // wrap="off": horizontal reveal via monospace text measurement.
      const lineStart = Math.max(before.lastIndexOf("\n"), before.lastIndexOf("\r")) + 1;
      const prefix = ta.value.slice(lineStart, scrollTarget.start);
      if (prefix.length === 0) {
        ta.scrollLeft = 0;
        return;
      }
      const ctx = document.createElement("canvas").getContext("2d");
      if (!ctx) return;
      const cs = getComputedStyle(ta);
      ctx.font = cs.font || `${cs.fontSize || "12px"} ${cs.fontFamily || "monospace"}`;
      const x = ctx.measureText(prefix).width;
      if (Number.isFinite(x)) ta.scrollLeft = Math.max(0, x - (ta.clientWidth || 0) / 3);
    } catch {
      // canvas adapter absent or measurement failed — vertical-only
    }
  }, [scrollTarget]);

  function requestScroll(range: MatchRange) {
    seqRef.current += 1;
    setScrollTarget({ start: range.start, end: range.end, seq: seqRef.current });
  }

  /** Re-anchor to the first match; used whenever the match set changes shape. */
  function resetSearchAnchor() {
    setActiveIndex(0);
    setNavigated(false);
  }

  function gotoNext() {
    if (matches.length === 0) return;
    const i = navigated ? (clampedIndex + 1) % matches.length : clampedIndex;
    setNavigated(true);
    setActiveIndex(i);
    requestScroll(matches[i]);
  }

  function gotoPrev() {
    if (matches.length === 0) return;
    const i = navigated ? (clampedIndex - 1 + matches.length) % matches.length : clampedIndex;
    setNavigated(true);
    setActiveIndex(i);
    requestScroll(matches[i]);
  }

  function pushUndo(snapshot: string) {
    setUndoStack((s) => [...s.slice(-(UNDO_LIMIT - 1)), snapshot]);
  }

  function replaceCurrent() {
    const m = clampedIndex === -1 ? undefined : matches[clampedIndex];
    if (!m) return;
    pushUndo(draft);
    const next = replaceRange(draft, m, replacement);
    // Recompute against the NEW text directly — the memo above still holds
    // the pre-replace set until React re-renders.
    const newMatches = findMatches(next, query, { caseSensitive, wholeWord });
    // Land on the match now occupying the edited region's position; starting
    // past the inserted text also skips matches the replacement itself
    // introduced (query ⊂ replacement must not loop).
    const idx = nextMatchIndex(newMatches, m.start + replacement.length);
    setDraft(next);
    setNavigated(true);
    setActiveIndex(idx === -1 ? 0 : idx);
    if (idx !== -1) requestScroll(newMatches[idx]);
  }

  function replaceAllAction() {
    if (matches.length === 0) return;
    pushUndo(draft);
    setDraft(replaceAllMatches(draft, matches, replacement));
    resetSearchAnchor();
    setScrollTarget(null);
  }

  function undoAction() {
    const prev = undoStack.at(-1);
    if (prev === undefined) return;
    setUndoStack((s) => s.slice(0, -1));
    setDraft(prev);
    resetSearchAnchor();
    setScrollTarget(null);
  }

  function openFindRow() {
    // Prefill from a single-line textarea selection, like the terminal
    // search overlay's select-then-find flow.
    const ta = textareaRef.current;
    if (ta) {
      const sel = draft.slice(ta.selectionStart ?? 0, ta.selectionEnd ?? 0);
      if (sel.length > 0 && !/[\r\n]/.test(sel)) {
        setQuery(sel);
        resetSearchAnchor();
      }
    }
    if (findOpen) {
      findInputRef.current?.focus();
      findInputRef.current?.select();
    } else {
      setFindOpen(true);
    }
  }

  function closeFindRow() {
    setFindOpen(false);
    textareaRef.current?.focus();
  }

  function onContentKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    // Cmd/Ctrl+F opens/refocuses the find row. The chord is free while the
    // dialog holds focus: hotkeys.ts binds no F, and the terminal's Cmd+F
    // handler lives in xterm's key handler, which requires terminal focus.
    if (isAccel(e.nativeEvent) && e.key.toLowerCase() === "f") {
      e.preventDefault();
      openFindRow();
      return;
    }
    // F3 / Shift+F3 cycle matches from anywhere in the dialog.
    if (e.key === "F3" && !e.altKey && !e.metaKey && !e.ctrlKey) {
      if (!findOpen || matches.length === 0) return;
      e.preventDefault();
      if (e.shiftKey) gotoPrev();
      else gotoNext();
    }
  }

  function onFindKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.nativeEvent.isComposing) return;
    if (e.key === "Enter") {
      e.preventDefault();
      if (query.length === 0) return;
      if (e.shiftKey) gotoPrev();
      else gotoNext();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      gotoNext();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      gotoPrev();
    }
  }

  function onReplaceKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.nativeEvent.isComposing) return;
    if (e.key === "Enter") {
      e.preventDefault();
      replaceCurrent();
    }
  }

  const counter =
    query.length === 0
      ? ""
      : matches.length === 0
        ? "No matches"
        : `${clampedIndex + 1} of ${matches.length}`;

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent
        className="sm:max-w-2xl"
        onKeyDown={onContentKeyDown}
        // Escape closes the find row first; preventDefault makes Radix skip
        // dismissal entirely (onOpenChange never fires). With the row closed
        // Escape cancels the dialog, as it always has. Never intercept
        // Escape on the inputs instead — Radix's document-level capture
        // handler has already run by then.
        onEscapeKeyDown={(e) => {
          // Read via the ref, never the closure — see findOpenRef above.
          if (findOpenRef.current) {
            e.preventDefault();
            closeFindRow();
          }
        }}
        onCloseAutoFocus={onCloseAutoFocus}
      >
        <AlertDialogHeader>
          <AlertDialogTitle>Paste multi-line content?</AlertDialogTitle>
          <AlertDialogDescription>
            The clipboard contains{" "}
            <span className="font-mono">
              {/* Count CRLF / CR / LF uniformly — a CR-only payload is
                  still one Enter per line to the remote shell. */}
              {draft ? draft.split(/\r\n|\r|\n/).length : 0}
            </span>{" "}
            lines. Pasting executes each newline as a separate command on the remote shell. You can
            edit the text below first — what you paste is exactly what's sent.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <div className="flex flex-col gap-1.5">
          <div className="flex justify-end">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground"
              aria-expanded={findOpen}
              title="Find & replace (⌘F / Ctrl+F)"
              data-testid="paste-find-toggle"
              onClick={openFindRow}
            >
              <Search /> Find &amp; replace
            </Button>
          </div>

          {findOpen && (
            <>
              <div className="flex items-center gap-1">
                <Input
                  ref={findInputRef}
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    resetSearchAnchor();
                  }}
                  onKeyDown={onFindKeyDown}
                  placeholder="Find"
                  aria-label="Find in paste"
                  autoComplete="off"
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  className="h-8 flex-1 font-mono text-xs"
                  data-testid="paste-find-input"
                />
                <span
                  data-testid="paste-find-counter"
                  aria-live="polite"
                  className="min-w-16 shrink-0 text-right font-mono text-xs tabular-nums text-muted-foreground"
                >
                  {counter}
                </span>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0"
                  onClick={gotoPrev}
                  disabled={matches.length === 0}
                  aria-label="Find previous"
                  title="Find previous (⇧↵ / ↑)"
                  data-testid="paste-find-prev"
                >
                  <ChevronUp />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0"
                  onClick={gotoNext}
                  disabled={matches.length === 0}
                  aria-label="Find next"
                  title="Find next (↵ / ↓)"
                  data-testid="paste-find-next"
                >
                  <ChevronDown />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className={cn("h-8 w-8 p-0", caseSensitive && "bg-accent text-accent-foreground")}
                  onClick={() => {
                    setCaseSensitive((v) => !v);
                    resetSearchAnchor();
                  }}
                  aria-pressed={caseSensitive}
                  aria-label="Match case"
                  title="Match case"
                  data-testid="paste-find-case"
                >
                  <CaseSensitive />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className={cn("h-8 w-8 p-0", wholeWord && "bg-accent text-accent-foreground")}
                  onClick={() => {
                    setWholeWord((v) => !v);
                    resetSearchAnchor();
                  }}
                  aria-pressed={wholeWord}
                  aria-label="Whole word"
                  title="Whole word"
                  data-testid="paste-find-word"
                >
                  <WholeWord />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0"
                  onClick={closeFindRow}
                  aria-label="Close find"
                  title="Close find (Esc)"
                  data-testid="paste-find-close"
                >
                  <X />
                </Button>
              </div>
              <div className="flex items-center gap-1">
                <Input
                  value={replacement}
                  onChange={(e) => setReplacement(e.target.value)}
                  onKeyDown={onReplaceKeyDown}
                  placeholder="Replace with"
                  aria-label="Replace with"
                  autoComplete="off"
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  className="h-8 flex-1 font-mono text-xs"
                  data-testid="paste-replace-input"
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8"
                  onClick={replaceCurrent}
                  disabled={clampedIndex === -1}
                  data-testid="paste-replace-one"
                >
                  Replace
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8"
                  onClick={replaceAllAction}
                  disabled={matches.length === 0}
                  data-testid="paste-replace-all"
                >
                  Replace all
                </Button>
                {undoStack.length > 0 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-8"
                    onClick={undoAction}
                    data-testid="paste-undo"
                  >
                    <Undo2 /> Undo
                  </Button>
                )}
              </div>
            </>
          )}

          <textarea
            ref={textareaRef}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            wrap="off"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            aria-label="Pending paste content"
            data-testid="paste-edit-textarea"
            className="max-h-64 min-h-24 w-full resize-y overflow-auto rounded border border-border bg-muted/30 p-2 font-mono text-xs"
          />
        </div>

        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => onConfirm(draft)} disabled={draft === ""}>
            Paste
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
