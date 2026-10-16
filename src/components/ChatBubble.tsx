import { useState, type ReactNode } from "react";

import { AlertCircle, Check, ChevronDown, ChevronRight, Copy, Save, Wrench } from "lucide-react";
import ReactMarkdown from "react-markdown";
import rehypeHighlight from "rehype-highlight";
import remarkGfm from "remark-gfm";

import "highlight.js/styles/github-dark.css";

import { saveChatSnippet, type ChatMessage } from "@/lib/api";
import { suggestedSnippetName } from "@/lib/snippets";
import { toastError, toastSuccess } from "@/lib/toast";

/**
 * One chat bubble. Cursor-matching style:
 *   - User messages: muted soft-rounded pill, right-aligned, plain
 *     text with `whitespace-pre-wrap` so newlines survive.
 *   - Assistant messages: plain markdown content (no bubble),
 *     left-aligned, GFM tables / strikethrough / task lists,
 *     fenced code blocks rendered with highlight.js syntax colors
 *     and a copy-to-clipboard affordance.
 *
 * `streaming` toggles a soft "still thinking" affordance — currently
 * just renders an inline pulsing cursor at the end of a partial
 * assistant message. The user-side bubble can't stream so the prop
 * is a no-op there.
 */
export function ChatBubble({
  message,
  streaming = false,
  canSaveSnippets = false,
}: {
  message: ChatMessage;
  streaming?: boolean;
  /** v6.3.0 — render a Save button on code blocks (Settings → Agent
   *  Chat, off by default). Passed down from the panel's settings query
   *  so this component stays provider-free (its XSS tests render bare). */
  canSaveSnippets?: boolean;
}) {
  if (message.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-2xl bg-primary/10 px-3 py-2">
          <p className="whitespace-pre-wrap break-words">{message.text}</p>
        </div>
      </div>
    );
  }

  if (message.role === "tool_use") {
    return <ToolUseBubble message={message} />;
  }

  return (
    <div className="markdown-body w-full leading-relaxed">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight]}
        components={{
          code: ({ className, children }) => {
            const match = /language-(\w+)/.exec(className ?? "");
            if (!match) {
              return (
                <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.9em]">
                  {children}
                </code>
              );
            }
            return (
              <CodeBlock
                language={match[1]}
                rawText={flattenText(children)}
                canSave={canSaveSnippets}
              >
                <code className={className}>{children}</code>
              </CodeBlock>
            );
          },
          // react-markdown wraps fenced code in <pre><code>; we
          // render the <pre> ourselves inside CodeBlock for control
          // over the header bar and overflow behavior.
          pre: ({ children }) => <>{children}</>,
          // Tighten default markdown spacing — Cursor-ish density.
          p: ({ children }) => <p className="my-2 first:mt-0 last:mb-0">{children}</p>,
          ul: ({ children }) => <ul className="my-2 list-disc pl-5">{children}</ul>,
          ol: ({ children }) => <ol className="my-2 list-decimal pl-5">{children}</ol>,
          li: ({ children }) => <li className="my-0.5">{children}</li>,
          h1: ({ children }) => <h1 className="my-3 text-[1.3em] font-semibold">{children}</h1>,
          h2: ({ children }) => <h2 className="my-3 text-[1.15em] font-semibold">{children}</h2>,
          h3: ({ children }) => <h3 className="my-2 text-[1em] font-semibold">{children}</h3>,
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {children}
            </a>
          ),
        }}
      >
        {message.text}
      </ReactMarkdown>
      {streaming && <StreamingCursor />}
    </div>
  );
}

/**
 * Phase 6 inline tool-use card. Chevron-collapsed by default —
 * the agent's tool calls shouldn't dominate the chat thread when
 * the user just wants the final answer. Click expands to show
 * full input + output. Failed calls (`is_error`) get an
 * alert-icon styling so a denied propose_command or dispatcher
 * crash is visually distinct from a successful read_scrollback.
 */
function ToolUseBubble({ message }: { message: Extract<ChatMessage, { role: "tool_use" }> }) {
  const [open, setOpen] = useState(false);
  const Icon = message.is_error ? AlertCircle : Wrench;
  const Chevron = open ? ChevronDown : ChevronRight;
  const label = humanizeToolName(message.name);
  return (
    <div
      className={`my-1 rounded-md border text-xs ${
        message.is_error ? "border-destructive/40 bg-destructive/5" : "border-border bg-muted/20"
      }`}
      data-testid="tool-use-bubble"
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-2 py-1.5 text-left hover:bg-accent/40"
        aria-expanded={open}
        aria-label={`${label} ${message.is_error ? "failed" : "succeeded"} — toggle details`}
      >
        <Chevron className="h-3 w-3 text-muted-foreground" />
        <Icon
          className={`h-3.5 w-3.5 ${
            message.is_error ? "text-destructive" : "text-muted-foreground"
          }`}
        />
        <span className="font-medium">{label}</span>
        <span className="ml-auto truncate font-mono text-muted-foreground">
          {summarize(message.input, message.output, message.is_error)}
        </span>
      </button>
      {open && (
        <div className="space-y-2 border-t bg-background/50 px-2 py-2">
          {message.input !== null && message.input !== undefined && (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                Input
              </div>
              <pre className="overflow-x-auto rounded bg-muted/40 px-2 py-1.5 font-mono text-[11px]">
                {JSON.stringify(message.input, null, 2)}
              </pre>
            </div>
          )}
          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">
              {message.is_error ? "Error" : "Output"}
            </div>
            <pre className="max-h-64 overflow-auto rounded bg-muted/40 px-2 py-1.5 font-mono text-[11px]">
              {message.output}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

function humanizeToolName(name: string): string {
  switch (name) {
    case "list_open_sessions":
      return "List sessions";
    case "read_scrollback":
      return "Read scrollback";
    case "propose_command":
      return "Run command";
    case "propose_api_call":
      return "Call API";
    case "ask_user":
      return "Ask user";
    default:
      return name;
  }
}

function summarize(input: unknown, output: string, isError: boolean): string {
  if (isError) {
    return output.slice(0, 80);
  }
  if (input && typeof input === "object") {
    const obj = input as Record<string, unknown>;
    if (typeof obj.command === "string") return obj.command as string;
    if (typeof obj.session_id === "string") return obj.session_id as string;
  }
  return "";
}

function StreamingCursor() {
  return (
    <span
      aria-hidden="true"
      className="ml-0.5 inline-block h-3.5 w-1.5 translate-y-0.5 animate-pulse bg-current"
    />
  );
}

function CodeBlock({
  language,
  rawText,
  canSave = false,
  children,
}: {
  language: string;
  rawText: string;
  canSave?: boolean;
  children: ReactNode;
}) {
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(rawText);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be denied (rare in Tauri 2 with the manager
      // plugin) — silently fail; the code is still selectable.
    }
  }

  // v6.3.0 — Save-to-file (Settings → Agent Chat, opt-in). The command
  // opens the NATIVE save dialog Rust-side and takes no path from us —
  // the click is the entire authority; a null result means the user
  // cancelled the dialog (not an error, no toast).
  async function save() {
    if (saving) return;
    setSaving(true);
    try {
      const path = await saveChatSnippet(rawText, suggestedSnippetName(language));
      if (path) toastSuccess("Saved", { description: path });
    } catch (err: unknown) {
      toastError("Couldn't save the code block", {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="my-2 overflow-hidden rounded-md border border-border">
      <div className="flex items-center justify-between border-b border-border bg-muted/40 px-2 py-1 text-[11px]">
        <span className="font-mono text-muted-foreground">{language}</span>
        <div className="flex items-center gap-1">
          {canSave && (
            <button
              type="button"
              onClick={() => void save()}
              disabled={saving}
              className="flex items-center gap-1 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent disabled:opacity-50"
              aria-label={saving ? "Saving code to a file" : "Save code to a file"}
              data-testid="code-block-save"
            >
              <Save className="h-3 w-3" /> {saving ? "Saving…" : "Save"}
            </button>
          )}
          <button
            type="button"
            onClick={() => void copy()}
            className="flex items-center gap-1 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent"
            aria-label={copied ? "Copied" : "Copy code"}
          >
            {copied ? (
              <>
                <Check className="h-3 w-3" /> Copied
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" /> Copy
              </>
            )}
          </button>
        </div>
      </div>
      <pre className="overflow-x-auto bg-[#0d1117] p-3 font-mono text-[0.9em]">{children}</pre>
    </div>
  );
}

/** Recursively flatten React children to a plain string (for copy). */
function flattenText(node: ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(flattenText).join("");
  if (typeof node === "object" && "props" in node) {
    const props = (node as { props?: { children?: ReactNode } }).props;
    return flattenText(props?.children);
  }
  return "";
}
