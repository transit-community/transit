import { useEffect, useMemo, useRef, useState } from "react";

import { useQuery } from "@tanstack/react-query";
import { Check, Copy, Eye, EyeOff, Send } from "lucide-react";

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
import { SaveRequestPopover } from "@/components/SaveRequestPopover";
import { Button } from "@/components/ui/button";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Input } from "@/components/ui/input";
import {
  apiPendingCert,
  apiSendRequest,
  apiSetSessionAuth,
  apiSessionHistory,
  apiTrustCert,
  closeApiSession,
  listApiSessions,
  registerApiSession,
  type ApiResponseWire,
} from "@/lib/api";
import {
  collectGetEndpoints,
  collectVarTokens,
  isDestructiveMethod,
  methodColor,
  sessionAuthHeaderFor,
  type CaptureRule,
} from "@/lib/apiCollections";
import { applyCaptureRules } from "@/lib/apiCapture";
import { apiBaseDisplay, bundledCollectionFor } from "@/lib/bundledCollections";
import { UntrustedCertDialog } from "@/components/dialogs/UntrustedCertDialog";
import { highlightJson } from "@/lib/jsonHighlight";
import { toastInfo } from "@/lib/toast";
import {
  extractInlinePlaceholders,
  extractVarTokens,
  isSensitiveVarName,
  isSessionOnlyVar,
  mergeVars,
  substituteVars,
  unfilledTokens,
  useApiVariablesStore,
} from "@/stores/apiVariablesStore";
import { useApiCollectionsStore } from "@/stores/apiCollectionsStore";
import {
  TERMINAL_FONT_FAMILY_DEFAULT,
  TERMINAL_FONT_SIZE_DEFAULT,
  useUiStore,
} from "@/stores/uiStore";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;
const BODYLESS = new Set(["GET", "HEAD"]);

/** Where each UniFi path token comes from — powers the Variables/help bar
 *  so an operator isn't left guessing (esp. consoleId). */
const PLACEHOLDER_HINTS: Record<string, string> = {
  consoleId: "Site Manager → List hosts (id)",
  id: "the id of the resource in this path",
  siteId: "Network → List sites (id)",
  deviceId: "Network → List devices (id)",
  clientId: "Network → List clients (id)",
  networkId: "Network → List networks (id)",
  cameraId: "Protect → List cameras (id)",
  voucherId: "List vouchers (id)",
  sdwanConfigId: "Site Manager → List SD-WAN configs (id)",
  portIdx: "switch port index (0-based)",
};

type HeaderRow = { key: string; value: string };
type Result = ApiResponseWire & { ms: number };

function statusColor(status: number): string {
  if (status >= 200 && status < 300) return "text-emerald-600 dark:text-emerald-400";
  if (status >= 300 && status < 400) return "text-blue-600 dark:text-blue-400";
  if (status >= 400 && status < 500) return "text-amber-600 dark:text-amber-400";
  return "text-destructive";
}

/**
 * v4.0.0 — the request surface for an API session tab. The
 * HUMAN path: any method (ungated), host-pinned + key-injected server-side
 * via `api_send_request`. The endpoint catalog lives in the left APIs
 * sidebar under the controller; clicking an endpoint there loads it here
 * (via the store's `pendingApiLoad`). The path box still accepts any custom
 * path. Write methods confirm before sending. The AI agent gets its own
 * GET-only tool later.
 */
export function ApiSessionPane({
  apiSessionId,
  sessionId,
  active,
}: {
  apiSessionId: string;
  sessionId: string;
  active: boolean;
}) {
  const [method, setMethod] = useState<string>("GET");
  const [path, setPath] = useState<string>("");
  const [headers, setHeaders] = useState<HeaderRow[]>([]);
  const [body, setBody] = useState<string>("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  // Self-signed cert TOFU (threat-model T40): the rejected fingerprint awaiting
  // the user's verify-and-trust confirm, + the in-flight trust+retry flag.
  const [untrustedFp, setUntrustedFp] = useState<string | null>(null);
  const [trusting, setTrusting] = useState(false);
  // Declarative response-capture rules for the loaded request (6c/6d): after a
  // response, pull a token/cookie into a {{variable}} for downstream requests.
  const [capture, setCapture] = useState<CaptureRule[]>([]);
  const [copied, setCopied] = useState(false);
  // Per-variable reveal toggle for masked (credential-shaped) variables.
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [confirmWrite, setConfirmWrite] = useState(false);
  // #12 Phase 2b session-history view: the full raw ring the agent reads
  // (null = showing the live response instead).
  const [historyText, setHistoryText] = useState<string | null>(null);
  // #17 — Body vs response-Headers view for the live response.
  const [responseView, setResponseView] = useState<"body" | "headers">("body");
  const pathRef = useRef<HTMLInputElement>(null);

  // Endpoint the sidebar asked this pane to load (keyed by tab sessionId).
  const pending = useUiStore((s) => s.pendingApiLoad[sessionId]);
  const consumeApiLoad = useUiStore((s) => s.consumeApiLoad);

  // The response pane inherits the monospace font from Settings (size +
  // family), same as the terminal — it's the same kind of content.
  const fontSize = useUiStore((s) => s.preferences.terminalFontSize) ?? TERMINAL_FONT_SIZE_DEFAULT;
  const fontFamily =
    useUiStore((s) => s.preferences.terminalFontFamily) ?? TERMINAL_FONT_FAMILY_DEFAULT;

  // Controller metadata (surface + host) drives the base-URL hint + path
  // placeholder. Server state, so it rides the shared query cache.
  const { data: sessions } = useQuery({ queryKey: ["apiSessions"], queryFn: listApiSessions });
  const meta = sessions?.find((s) => s.id === apiSessionId);
  // #12 Phase 2b: gather this controller's collection GET endpoints (bundled +
  // user) to push down to the agent's known-endpoints prompt on register.
  const userCollections = useApiCollectionsStore((s) => s.byController[apiSessionId]);
  const knownEndpoints = useMemo(() => {
    const bundled = meta ? bundledCollectionFor(meta.vendor, meta.kind) : null;
    return collectGetEndpoints([...(bundled ? [bundled] : []), ...(userCollections ?? [])]);
  }, [meta, userCollections]);
  const baseDisplay = meta ? apiBaseDisplay(meta) : "";

  // Per-controller variables ({{consoleId}} etc.) — set once, substituted
  // into the path/body at send. Select the stable stored object (or none)
  // to avoid a new-object re-render each store tick.
  const varsRaw = useApiVariablesStore((s) => s.variables[apiSessionId]);
  const capturedRaw = useApiVariablesStore((s) => s.captured[apiSessionId]);
  // Merged view for substitution + the Variables bar: persisted user vars plus
  // the in-memory captured tokens (captured wins — a fresh login token beats a
  // stale saved value). Captured tokens (T40) are never persisted.
  const vars = useMemo(() => mergeVars(varsRaw, capturedRaw), [varsRaw, capturedRaw]);
  // The same map minus anything credential-shaped — the ONLY map allowed to
  // fill a URL path (see the call site in `send`).
  const pathVars = useMemo(() => {
    const out = Object.fromEntries(
      Object.entries(vars).filter(([k]) => !isSensitiveVarName(k)),
    ) as Record<string, string>;
    // The username is NOT secret and the backend deliberately does not
    // substitute the path, so fill it here — otherwise a custom
    // `users/{{username}}/sessions` reaches the wire as a literal, gets
    // percent-encoded, and `confine` refuses it with "escapes the API base".
    if (meta?.auth.scheme === "login_credentials") out.username = meta.auth.username;
    return out;
  }, [vars, meta]);

  // With the `login_credentials` scheme the operator never types these: the
  // backend substitutes them from the session's stored credential at send
  // (Rule 1 — the password never crosses IPC, so the field shows a chip, not
  // a value). Anything else the collection needs is still typed here.
  const backendFilled = useMemo(
    () =>
      meta?.auth.scheme === "login_credentials"
        ? new Set(["username", "password"])
        : new Set<string>(),
    [meta],
  );
  const setVariable = useApiVariablesStore((s) => s.setVariable);
  const setCapturedVariable = useApiVariablesStore((s) => s.setCapturedVariable);
  // Variables can live in the path, the body ({{username}}/{{password}} on a
  // login POST), or a header value (Cookie: …={{apicToken}}), so surface tokens
  // from all three — otherwise a login-flow request has no way to fill them.
  const varTokens = useMemo(
    () => extractVarTokens([path, body, ...headers.map((h) => h.value)].join("\n")),
    [path, body, headers],
  );
  const inlinePlaceholders = useMemo(() => extractInlinePlaceholders(path), [path]);

  // Response → variable: right-click a highlighted value in the response to
  // save it as a {{variable}} (e.g. consoleId), reused across the collection.
  const [selection, setSelection] = useState("");
  // Offer the variables THIS controller's collection actually uses. The old
  // list was a hardcoded UniFi set (consoleId/siteId/cameraId/…), so every
  // non-UniFi vendor was offered the wrong vocabulary and Meraki's
  // {{organizationId}} — the one id it cannot start without — was absent. Also
  // fixes a circularity: keying off `Object.keys(vars)` alone meant a variable
  // only became right-clickable AFTER it already had a value, so a response
  // could never bootstrap the first one.
  const varNames = useMemo(() => {
    const bundled = meta ? bundledCollectionFor(meta.vendor, meta.kind) : null;
    const fromCollections = collectVarTokens([
      ...(bundled ? [bundled] : []),
      ...(userCollections ?? []),
    ]);
    const fromRequest = extractVarTokens([path, body, ...headers.map((h) => h.value)].join("\n"));
    // Also exclude the collection's SESSION-TOKEN variables (apicToken,
    // jsessionid, …). Those aren't credential-shaped by NAME, so setting one
    // before its capture rule has fired would route to `setVariable` and
    // persist a live login token to localStorage — undoing T40 by the back
    // door. `sessionAuthHeaderFor` identifies them structurally: a variable
    // the collection carries in an auth header IS a session credential.
    const pool = [...(bundled ? [bundled] : []), ...(userCollections ?? [])];
    return [...new Set([...fromCollections, ...fromRequest, ...Object.keys(vars)])]
      .filter(
        (n) => !isSensitiveVarName(n) && !backendFilled.has(n) && !sessionAuthHeaderFor(pool, n),
      )
      .sort();
  }, [meta, userCollections, path, body, headers, vars, backendFilled]);
  const setAsVariable = (name: string) => {
    if (!selection) return;
    // If the target is a captured token (in-memory, T40), keep it in memory —
    // a right-click must not persist a live login token to localStorage while
    // the "session" badge claims it isn't saved (v4.3.0 adversarial review).
    const set = capturedRaw?.[name] !== undefined ? setCapturedVariable : setVariable;
    set(apiSessionId, name, selection);
    const shown = selection.length > 40 ? selection.slice(0, 40) + "…" : selection;
    toastInfo(`Set {{${name}}} = ${shown}`);
  };

  // Panes stay mounted across tab switches (forceMount), so focus doesn't
  // follow the active tab on its own — land the cursor in the path box
  // when this controller becomes active, so typing can start at once.
  useEffect(() => {
    if (active) pathRef.current?.focus();
  }, [active]);

  // register-on-open: tell the backend this controller is an OPEN session so
  // the agent sees it (list_open_sessions) and can propose the FIRST GET
  // itself — the human need not send a request first. Deregister on unmount
  // (tab close; panes are forceMount-kept across switches, so unmount ==
  // close, and openApiTab dedups to one tab per controller so this is 1:1).
  //
  // L2 (accepted, LOW — adversarial review): these two IPCs are
  // fire-and-forget, and Tauri doesn't guarantee it processes a close before
  // a same-controller re-open's register. The common direction is
  // fail-closed (a lost register just hides the controller until the next
  // send/remount); the reverse (register lands after close) leaves an EMPTY,
  // still-fully-gated (GET-only, host-pinned, scoped) ring with no tab — no
  // boundary breach — and needs a rare open-then-instant-close race. A true
  // fix (per-controller sequence token) is disproportionate; revisit if the
  // tab lifecycle grows.
  // Register on open + re-send the known endpoints whenever the collection
  // changes, so the agent's known-endpoints prompt stays current. NO close in
  // this effect — a collection edit must NOT drop the ring; the close lives in
  // its own effect below, keyed only on the controller id.
  useEffect(() => {
    void registerApiSession(apiSessionId, knownEndpoints);
  }, [apiSessionId, knownEndpoints]);
  useEffect(() => {
    return () => {
      void closeApiSession(apiSessionId);
    };
  }, [apiSessionId]);

  // A sidebar endpoint click stashes a template for this tab; load it into
  // the request builder (no auto-send) and clear it.
  useEffect(() => {
    if (!pending) return;
    setMethod(pending.method);
    setPath(pending.path);
    setHeaders(pending.headers.map((h) => ({ key: h.key, value: h.value })));
    setBody(pending.body ?? "");
    setCapture(pending.capture ?? []);
    setError(null);
    setResult(null);
    setCopied(false);
    consumeApiLoad(sessionId);
    requestAnimationFrame(() => pathRef.current?.focus());
  }, [pending, sessionId, consumeApiLoad]);

  const isWrite = isDestructiveMethod(method);

  const send = async () => {
    if (sending) return;
    setSending(true);
    setError(null);
    setCopied(false);
    const t0 = performance.now();
    try {
      // Substitute {{variables}} into the path, body, AND header values (the
      // login-flow auth header carries the captured token, e.g. Cookie:
      // APIC-cookie={{apicToken}}) just before sending.
      const wireHeaders = headers
        .filter((h) => h.key.trim() !== "")
        .map((h) => [h.key.trim(), substituteVars(h.value, vars)] as [string, string]);
      // A credential must never be substituted into the PATH. The backend
      // refuses a `{{password}}` MARKER there, but that guard is defeated if
      // the frontend has already replaced the marker with the value — the
      // resulting path is recorded verbatim into the agent-visible session
      // ring by `record_exchange`, and into the controller's access log. So
      // path substitution deliberately uses a credential-free view: a
      // credential token survives to the backend, where the guard rejects it
      // with a message that explains why. Body + header values keep the full
      // map (that is where a credential legitimately belongs).
      const finalPath = substituteVars(path, pathVars);
      const wireBody =
        BODYLESS.has(method) || body.trim() === "" ? null : substituteVars(body, vars);
      const resp = await apiSendRequest(apiSessionId, method, finalPath, wireHeaders, wireBody);
      setResult({ ...resp, ms: Math.round(performance.now() - t0) });
      // Declarative capture (6c/6d): pull configured values (a login token in
      // the body, a Set-Cookie session id) into {{variables}} for downstream
      // requests — no manual right-click needed.
      const captured = applyCaptureRules(capture, { body: resp.body, headers: resp.headers });
      // Captured tokens go to the in-memory layer only — never localStorage (T40).
      for (const c of captured) setCapturedVariable(apiSessionId, c.into, c.value);
      if (captured.length > 0) {
        toastInfo(`Captured ${captured.map((c) => `{{${c.into}}}`).join(", ")}`);
        // Hand the resulting auth header to the backend so the AGENT's GETs can
        // ride this session. Derived from the collection's own requests, so it
        // works for any login-flow vendor (ACI's APIC-cookie, vManage's
        // JSESSIONID, Apstra's AuthToken, Aruba's Bearer) without a per-vendor
        // table. Do it HERE, at capture time — the operator normally asks the
        // agent immediately, without sending an investigation request first.
        const bundled = meta ? bundledCollectionFor(meta.vendor, meta.kind) : null;
        const pool = [...(bundled ? [bundled] : []), ...(userCollections ?? [])];
        for (const c of captured) {
          const hdr = sessionAuthHeaderFor(pool, c.into);
          if (!hdr) continue;
          const value = substituteVars(hdr.template, { ...vars, [c.into]: c.value });
          void apiSetSessionAuth(apiSessionId, hdr.name, value).catch(() => {
            // Non-fatal: the human path is unaffected; only agent replay is.
          });
          break;
        }
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // A TLS/transport failure to a self-signed controller: surface the
      // rejected fingerprint for TOFU verification instead of a dead-end error.
      if (/transport error|error sending request|certificate/i.test(msg)) {
        try {
          const fp = await apiPendingCert(apiSessionId);
          if (fp) {
            setUntrustedFp(fp);
            setResult(null);
            return;
          }
        } catch {
          /* no pending cert — fall through to the plain error */
        }
      }
      setError(msg);
      setResult(null);
    } finally {
      setSending(false);
    }
  };

  /** The user verified + accepted the self-signed cert in the dialog: pin it,
   *  then retry the request that triggered the prompt. */
  const handleTrustCert = async () => {
    if (!untrustedFp) return;
    setTrusting(true);
    try {
      await apiTrustCert(apiSessionId, untrustedFp);
      setUntrustedFp(null);
      await send();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setUntrustedFp(null);
    } finally {
      setTrusting(false);
    }
  };

  /** Send, but confirm first for a write method (the human path is
   *  ungated, so this modal is the only speed bump before a live change). */
  const onSendClick = () => {
    if (sending) return;
    // Block on any unfilled token BEFORE it reaches the confine gate — a
    // literal `{{siteId}}`/`{siteId}` in the path is percent-encoded and
    // refused as "escapes the API base", which reads like a security error.
    // Block on unfilled tokens in the body + header values too, not just the
    // path — a login POST needs {{username}}/{{password}}, an investigation GET
    // needs its {{token}} header filled before it can authenticate.
    const checkText = [path, BODYLESS.has(method) ? "" : body, ...headers.map((h) => h.value)].join(
      "\n",
    );
    const missing = unfilledTokens(checkText, vars).filter((t) => !backendFilled.has(t));
    if (missing.length > 0) {
      const fmt = (t: string) => (varTokens.includes(t) ? `{{${t}}}` : `{${t}}`);
      setError(`Set a value for ${missing.map(fmt).join(", ")} before sending.`);
      return;
    }
    setError(null);
    if (isWrite) setConfirmWrite(true);
    else void send();
  };

  const pretty = useMemo(() => {
    if (!result) return { text: "", isJson: false };
    try {
      return { text: JSON.stringify(JSON.parse(result.body), null, 2), isJson: true };
    } catch {
      return { text: result.body, isJson: false };
    }
  }, [result]);

  const bodySize = result ? new TextEncoder().encode(result.body).length : 0;

  // Response headers as copy-ready `name: value` lines (#17).
  const headersText = useMemo(
    () => (result ? result.headers.map(([k, v]) => `${k}: ${v}`).join("\n") : ""),
    [result],
  );

  // Copy the currently-shown response view (body or headers).
  const copyResponse = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(responseView === "headers" ? headersText : pretty.text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable/denied — nothing actionable to surface.
    }
  };

  // Toggle the session-history view (the full ring the agent reads). Refetch
  // each open so it reflects any agent GETs made since.
  const toggleHistory = async () => {
    if (historyText !== null) {
      setHistoryText(null);
      return;
    }
    try {
      setHistoryText(await apiSessionHistory(apiSessionId));
    } catch {
      setHistoryText("(couldn't load session history)");
    }
  };

  const copyHistory = async () => {
    if (historyText === null) return;
    try {
      await navigator.clipboard.writeText(historyText);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable/denied — nothing actionable to surface.
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      {/* Request bar */}
      <div className="flex items-center gap-2 border-b border-border p-2">
        <select
          value={method}
          onChange={(e) => setMethod(e.target.value)}
          className={`h-9 shrink-0 rounded-md border border-input bg-background px-2 text-sm font-semibold focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring ${methodColor(method)}`}
          aria-label="HTTP method"
        >
          {METHODS.map((m) => (
            <option key={m} value={m} className="text-foreground">
              {m}
            </option>
          ))}
        </select>
        <div className="flex h-9 min-w-0 flex-1 items-center rounded-md border border-input bg-background focus-within:ring-1 focus-within:ring-ring">
          {baseDisplay && (
            <span
              className="max-w-[45%] shrink-0 truncate border-r border-border px-2 py-1 font-mono text-[11px] text-muted-foreground"
              title={`Requests go to ${baseDisplay}/ + your path (host is fixed to the controller)`}
            >
              {baseDisplay}
            </span>
          )}
          <input
            ref={pathRef}
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSendClick();
            }}
            placeholder={
              meta?.kind === "site_manager" ? "/v1/sites" : "sites  (relative to the base above)"
            }
            className="h-full min-w-0 flex-1 bg-transparent px-2 font-mono text-xs outline-none"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            aria-label="Request path"
          />
        </div>
        <SaveRequestPopover
          apiSessionId={apiSessionId}
          request={{
            method,
            path,
            headers,
            body: !BODYLESS.has(method) && body.trim() !== "" ? body : null,
          }}
        />
        <Button onClick={onSendClick} disabled={sending} className="shrink-0 gap-1.5">
          <Send className="h-3.5 w-3.5" />
          {sending ? "Sending..." : "Send"}
        </Button>
      </div>

      {/* Variables + placeholder help — appears when the path has tokens.
          {{vars}} are set once here (persisted) and substituted at send;
          {single} placeholders are edited inline in the path. */}
      {(varTokens.length > 0 || inlinePlaceholders.length > 0) && (
        <div className="flex flex-col gap-1.5 border-b border-border bg-muted/20 px-2 py-1.5">
          {varTokens.map((name) => {
            const secret = isSensitiveVarName(name);
            // Masked + memory-only for a credential-shaped name; memory-only
            // (already) for a response-captured token. Both get the badge.
            const sessionOnly = isSessionOnlyVar(name, capturedRaw);
            const fromStore = backendFilled.has(name);
            return (
              <div key={name} className="flex items-center gap-2">
                <label className="w-24 shrink-0 font-mono text-[11px] text-muted-foreground">
                  {`{{${name}}}`}
                </label>
                {fromStore ? (
                  <div className="flex h-7 flex-1 items-center gap-2 rounded-md border border-dashed border-border bg-muted/40 px-2">
                    <span className="font-mono text-xs text-muted-foreground">
                      {name === "username" && meta?.auth.scheme === "login_credentials"
                        ? meta.auth.username
                        : "\u2022".repeat(8)}
                    </span>
                    <span
                      className="rounded bg-emerald-500/15 px-1 text-[9px] font-medium text-emerald-700 dark:text-emerald-400"
                      title="Filled from this controller's stored credential when the request is sent — the value never leaves the backend"
                    >
                      from stored credential
                    </span>
                  </div>
                ) : (
                  <Input
                    type={secret && !revealed[name] ? "password" : "text"}
                    value={vars[name] ?? ""}
                    onChange={(e) =>
                      // The store redirects credential-shaped names to the
                      // in-memory layer itself; a captured token stays in memory
                      // when edited; everything else persists as before.
                      (capturedRaw?.[name] !== undefined ? setCapturedVariable : setVariable)(
                        apiSessionId,
                        name,
                        e.target.value,
                      )
                    }
                    placeholder={PLACEHOLDER_HINTS[name] ?? "value"}
                    className="h-7 flex-1 font-mono text-xs"
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                    autoComplete={secret ? "off" : undefined}
                    aria-label={`Variable ${name}`}
                  />
                )}
                {!fromStore && secret && (
                  <button
                    type="button"
                    onClick={() => setRevealed((r) => ({ ...r, [name]: !r[name] }))}
                    className="shrink-0 rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                    aria-label={revealed[name] ? `Hide ${name}` : `Show ${name}`}
                    title={revealed[name] ? "Hide" : "Show"}
                  >
                    {revealed[name] ? (
                      <EyeOff className="h-3.5 w-3.5" />
                    ) : (
                      <Eye className="h-3.5 w-3.5" />
                    )}
                  </button>
                )}
                {!fromStore && sessionOnly && (
                  <span
                    className="shrink-0 rounded bg-amber-500/15 px-1 text-[9px] font-medium text-amber-700 dark:text-amber-400"
                    title={
                      secret
                        ? "A credential — held in memory for this session only, never saved to disk"
                        : "Captured this session from a response — held in memory, not saved to disk"
                    }
                  >
                    session
                  </span>
                )}
                {PLACEHOLDER_HINTS[name] && (
                  <span className="hidden shrink-0 text-[11px] text-muted-foreground sm:inline">
                    from {PLACEHOLDER_HINTS[name]}
                  </span>
                )}
              </div>
            );
          })}
          {inlinePlaceholders.length > 0 && (
            <p className="text-[11px] text-muted-foreground">
              Fill inline in the path:{" "}
              {inlinePlaceholders
                .map((p) => `{${p}} — ${PLACEHOLDER_HINTS[p] ?? "an id"}`)
                .join("  ·  ")}
            </p>
          )}
          {varTokens.length > 0 && (
            <p className="text-[11px] text-muted-foreground">
              Tip: send a listing (e.g. List hosts), then highlight an id in the response and
              right-click → <span className="font-medium">Set selection as variable</span>.
            </p>
          )}
        </div>
      )}

      {/* Request options: headers + body */}
      <div className="max-h-[38%] shrink-0 overflow-auto border-b border-border">
        <div className="p-2">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Headers</span>
            <button
              type="button"
              onClick={() => setHeaders((h) => [...h, { key: "", value: "" }])}
              className="rounded px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
            >
              + Add
            </button>
          </div>
          {headers.length === 0 ? (
            <p className="px-1 py-1 text-xs text-muted-foreground">
              No custom headers. <span className="font-mono">X-API-KEY</span> is injected
              automatically.
            </p>
          ) : (
            <div className="grid gap-1">
              {headers.map((h, i) => (
                <div key={i} className="flex items-center gap-1">
                  <Input
                    value={h.key}
                    onChange={(e) =>
                      setHeaders((rows) =>
                        rows.map((r, j) => (j === i ? { ...r, key: e.target.value } : r)),
                      )
                    }
                    placeholder="Header"
                    className="h-8 flex-1 font-mono text-xs"
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                  />
                  <Input
                    value={h.value}
                    onChange={(e) =>
                      setHeaders((rows) =>
                        rows.map((r, j) => (j === i ? { ...r, value: e.target.value } : r)),
                      )
                    }
                    placeholder="Value"
                    className="h-8 flex-1 font-mono text-xs"
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                  />
                  <button
                    type="button"
                    onClick={() => setHeaders((rows) => rows.filter((_, j) => j !== i))}
                    className="rounded px-1.5 text-muted-foreground hover:text-destructive"
                    aria-label="Remove header"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}

          {!BODYLESS.has(method) && (
            <div className="mt-3">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Body</span>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder='{ "key": "value" }'
                className="h-24 w-full rounded-md border border-input bg-background p-2 font-mono text-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
              />
            </div>
          )}
        </div>
      </div>

      {/* Response */}
      <div className="flex min-h-0 flex-1 flex-col">
        {/* Response / Session-history toggle — always available. The history
            is the full ring the agent reads (yours + the agent's GETs); the
            live-response pane only ever shows your last send. */}
        <div className="flex items-center gap-2 border-b border-border px-3 py-1 text-xs">
          <button
            type="button"
            onClick={() => void toggleHistory()}
            className="rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            {historyText !== null ? "← Back to response" : "Session history"}
          </button>
          {historyText !== null && (
            <>
              <span className="text-muted-foreground">
                the full request/response log the agent reads
              </span>
              <button
                type="button"
                onClick={() => void copyHistory()}
                className="ml-auto flex items-center gap-1 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                title="Copy session history"
                aria-label="Copy session history"
              >
                {copied ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copied ? "Copied" : "Copy"}
              </button>
            </>
          )}
        </div>
        {result && historyText === null && (
          <div className="flex items-center gap-4 border-b border-border px-3 py-1.5 text-xs">
            <span className={`font-semibold ${statusColor(result.status)}`}>
              Status: {result.status}
            </span>
            <span className="text-muted-foreground">Time: {result.ms} ms</span>
            <span className="text-muted-foreground">Size: {bodySize} B</span>
            {result.truncated && (
              <span className="text-amber-600 dark:text-amber-400">truncated (8 MiB cap)</span>
            )}
            <div className="ml-auto flex items-center gap-2">
              {/* #17 — Body vs response Headers view. */}
              <div className="flex overflow-hidden rounded border border-border">
                {(["body", "headers"] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setResponseView(v)}
                    className={
                      responseView === v
                        ? "bg-accent px-1.5 py-0.5 font-medium text-foreground"
                        : "px-1.5 py-0.5 text-muted-foreground hover:bg-accent/50"
                    }
                  >
                    {v === "body"
                      ? "Body"
                      : `Headers${result.headers.length ? ` (${result.headers.length})` : ""}`}
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={() => void copyResponse()}
                className="flex items-center gap-1 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                title={responseView === "headers" ? "Copy response headers" : "Copy response body"}
                aria-label={
                  responseView === "headers" ? "Copy response headers" : "Copy response body"
                }
              >
                {copied ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-auto p-3">
          {historyText !== null ? (
            <pre
              className="whitespace-pre-wrap break-words text-muted-foreground"
              style={{ fontSize: `${fontSize}px`, fontFamily }}
            >
              {historyText || "(no history yet — send a request, or ask the agent to investigate)"}
            </pre>
          ) : error ? (
            <div
              className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          ) : result && responseView === "headers" ? (
            <div style={{ fontSize: `${fontSize}px`, fontFamily }}>
              {result.headers.length === 0 ? (
                <p className="text-muted-foreground">(no response headers)</p>
              ) : (
                <div className="space-y-1">
                  {result.headers.map(([k, v], i) => (
                    <div
                      key={`${k}-${i}`}
                      className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-3"
                    >
                      <span className="break-words font-semibold text-muted-foreground">{k}</span>
                      <span className="break-words text-foreground">{v}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : result ? (
            <ContextMenu
              onOpenChange={(open) => {
                // Capture the highlighted text when the menu opens (a
                // right-click preserves the selection).
                if (open) setSelection(window.getSelection()?.toString().trim() ?? "");
              }}
            >
              <ContextMenuTrigger asChild>
                <pre
                  className="whitespace-pre-wrap break-words text-foreground"
                  style={{ fontSize: `${fontSize}px`, fontFamily }}
                >
                  {pretty.isJson ? highlightJson(pretty.text) : pretty.text}
                </pre>
              </ContextMenuTrigger>
              <ContextMenuContent className="max-w-xs">
                {selection ? (
                  <>
                    <ContextMenuItem onSelect={() => void navigator.clipboard.writeText(selection)}>
                      Copy selection
                    </ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuSub>
                      <ContextMenuSubTrigger>Set selection as variable</ContextMenuSubTrigger>
                      <ContextMenuSubContent className="max-h-72 overflow-y-auto">
                        {varNames.map((name) => (
                          <ContextMenuItem key={name} onSelect={() => setAsVariable(name)}>
                            <span className="font-mono text-xs">{`{{${name}}}`}</span>
                          </ContextMenuItem>
                        ))}
                      </ContextMenuSubContent>
                    </ContextMenuSub>
                  </>
                ) : (
                  <ContextMenuItem disabled>
                    Highlight a value first, then right-click
                  </ContextMenuItem>
                )}
              </ContextMenuContent>
            </ContextMenu>
          ) : (
            <div className="flex h-full items-center justify-center text-center text-sm text-muted-foreground">
              <div>
                <p>Pick an endpoint under this controller in the sidebar, or enter a path.</p>
                <p className="mt-1 text-xs">
                  The AI agent can investigate this controller read-only from the chat panel.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      <AlertDialog open={confirmWrite} onOpenChange={setConfirmWrite}>
        <AlertDialogContent
          onCloseAutoFocus={(e) => {
            e.preventDefault();
            pathRef.current?.focus();
          }}
        >
          <AlertDialogHeader>
            <AlertDialogTitle>
              Send a <span className={methodColor(method)}>{method}</span> to your live controller?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This is a write to{" "}
              <span className="font-mono">{baseDisplay || "the controller"}</span>. It changes real
              state (the AI agent can never do this — investigate-only). Continue?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                setConfirmWrite(false);
                void send();
              }}
            >
              Send {method}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <UntrustedCertDialog
        fingerprint={untrustedFp}
        host={baseDisplay || undefined}
        busy={trusting}
        onTrust={() => void handleTrustCert()}
        onCancel={() => setUntrustedFp(null)}
      />
    </div>
  );
}
