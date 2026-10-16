import { create } from "zustand";

/**
 * v4.0.0 — per-controller API variables (Postman-style environment values).
 *
 * The stable one is `consoleId` — needed in every Network/Protect connector
 * path but the same for a given console — so the operator sets it ONCE here
 * instead of pasting it into each request. Values substitute into `{{name}}`
 * tokens at send time. Persisted to localStorage, keyed by api_session id.
 *
 * Most are NON-SECRET substitution values (site ids, console ids) and plain
 * localStorage is the right home for them. Two kinds are NOT, and never touch
 * disk: response-captured login tokens (T40) live in `captured`, and
 * credential-shaped names (`isSensitiveVarName` — v4.3.0's login-flow
 * collections put a real `{{password}}` in the variables bar) are redirected
 * there too. The API key itself is never here at all — it is a `SecretRef`
 * resolved Rust-side. Nothing here crosses the agent boundary.
 */

const STORAGE_KEY = "transit.apiVariables";

type VarMap = Record<string, Record<string, string>>; // apiSessionId -> { name: value }

/**
 * Variable names that hold a LIVE CREDENTIAL and must never reach
 * localStorage — masked in the UI and held in memory only, exactly like a
 * captured login token (T40).
 *
 * v4.3.0's login-flow collections made this necessary: every bundled vendor
 * now ships a login request whose body carries `{{username}}`/`{{password}}`,
 * so the operator types a real password into the variables bar. Before this,
 * variables really were only non-secret ids (console/site ids) and plain
 * localStorage was the right home.
 *
 * Deliberately NOT matched: `token` / `apiKey`. A response-captured token
 * already lives in `captured` (in-memory) via the capture rules, and a
 * long-lived API key belongs in the session's auth scheme (keychain-backed),
 * not in a variable — matching those names here would only surprise someone
 * who deliberately parked a non-secret value under such a name.
 */
/** Credential words, matched against the variable name's WORDS rather than as
 *  a substring — a substring test swept in `bypass`, `passive`,
 *  `passthrough`. Deliberately excludes `key`/`token`: a captured token is
 *  already in-memory via the capture rules, and an API key belongs in the
 *  session's keychain-backed auth scheme, not a variable. */
const CREDENTIAL_WORDS = new Set([
  "password",
  "passwd",
  "passphrase",
  "pwd",
  "secret",
  "credential",
  "credentials",
  "psk",
  "otp",
  "pin",
  "privkey",
]);

/** Split a variable name into lowercase words on separators AND camelCase
 *  boundaries: `j_password` → [j, password], `clientSecret` → [client,
 *  secret], `bypass` → [bypass]. */
function varNameWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s_\-.]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

/** Roots unambiguous enough to match as a SUBSTRING, catching the
 *  all-lowercase compounds the word-split misses — `secretkey` (FortiGate's
 *  real `/logincheck` parameter), `authpassword`, `sharedsecret`, `userpwd`.
 *  Anchoring on these four rather than on `pass` is what keeps `bypass`,
 *  `passive` and `passthrough` out. */
const CREDENTIAL_ROOTS = ["password", "passwd", "passphrase", "secret"];

export function isSensitiveVarName(name: string): boolean {
  if (varNameWords(name).some((w) => CREDENTIAL_WORDS.has(w))) return true;
  const lower = name.toLowerCase();
  return CREDENTIAL_ROOTS.some((r) => lower.includes(r));
}

/** Read the persisted variables, dropping anything malformed or
 *  credential-shaped. Exported so the purge is directly testable. */
export function loadPersistedVariables(): VarMap {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return {};
    // Keep only string→(string→string) shape; drop anything malformed.
    const out: VarMap = {};
    let dropped = false;
    for (const [sid, vars] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof vars !== "object" || vars === null) continue;
      const clean: Record<string, string> = {};
      for (const [k, v] of Object.entries(vars as Record<string, unknown>)) {
        // One-way purge: a build before the sensitive-name rule could have
        // persisted a real password here. Drop it on load rather than
        // carrying a plaintext credential forward.
        if (typeof v === "string" && !isSensitiveVarName(k)) clean[k] = v;
      }
      if (Object.keys(clean).length !== Object.keys(vars as object).length) dropped = true;
      out[sid] = clean;
    }
    // The purge has to reach DISK, not just the returned object: `setVariable`
    // never rewrites storage for a credential-shaped name (it redirects to the
    // in-memory layer and returns early), so without this the plaintext a
    // pre-v4.3.0 build persisted would sit in localStorage indefinitely.
    if (dropped) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(out));
      } catch {
        // Storage full / disabled — the in-memory value is still purged.
      }
    }
    return out;
  } catch {
    return {};
  }
}

interface ApiVariablesState {
  variables: VarMap;
  /**
   * In-memory ONLY, never persisted (T40 hardening): the outputs of
   * declarative response-capture rules — login tokens and session cookies.
   * Those are live credentials, so they must not touch localStorage; they die
   * on reload / when the app closes and are re-captured by re-running the
   * "Log in first" request. User-set variables + right-click captures (site
   * ids, console ids — non-secret) stay in `variables` and persist as before.
   */
  captured: VarMap;
  setVariable: (apiSessionId: string, name: string, value: string) => void;
  setCapturedVariable: (apiSessionId: string, name: string, value: string) => void;
}

/** True when this variable is held in memory only — a response-captured token
 *  or a credential-shaped name. Drives the "session" badge + input masking. */
export function isSessionOnlyVar(name: string, captured: Record<string, string> | undefined) {
  return isSensitiveVarName(name) || captured?.[name] !== undefined;
}

export const useApiVariablesStore = create<ApiVariablesState>((set) => ({
  variables: loadPersistedVariables(),
  captured: {},
  setVariable: (apiSessionId, name, value) =>
    set((s) => {
      // Defense in depth: a credential-shaped name is redirected to the
      // in-memory layer HERE, in the store, so every call site (the variables
      // bar, the right-click "set selection as variable", any future caller)
      // is covered rather than each having to remember.
      if (isSensitiveVarName(name)) {
        return {
          captured: {
            ...s.captured,
            [apiSessionId]: { ...s.captured[apiSessionId], [name]: value },
          },
        };
      }
      const next: VarMap = {
        ...s.variables,
        [apiSessionId]: { ...s.variables[apiSessionId], [name]: value },
      };
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Storage full / disabled — keep the in-memory value regardless.
      }
      return { variables: next };
    }),
  setCapturedVariable: (apiSessionId, name, value) =>
    // Deliberately NO localStorage write — a captured token is a session-only
    // credential (T40). It lives in memory for substitution this session only.
    set((s) => ({
      captured: {
        ...s.captured,
        [apiSessionId]: { ...s.captured[apiSessionId], [name]: value },
      },
    })),
}));

/**
 * All variables for a session, for substitution + display: the persisted
 * user-set values PLUS the in-memory captured tokens, with captured WINNING (a
 * fresh login token supersedes any stale saved value). Captured tokens are
 * never persisted (T40) — they exist only in `captured`.
 */
export function mergeVars(
  userVars: Record<string, string> = {},
  capturedVars: Record<string, string> = {},
): Record<string, string> {
  return { ...userVars, ...capturedVars };
}

/** Substitute `{{name}}` tokens from `vars`. An unknown token is left
 *  verbatim (so it's visible that it wasn't filled, rather than silently
 *  emptied into a wrong URL). Single-brace `{placeholder}` tokens are NOT
 *  touched — those are per-request values the operator edits inline. */
export function substituteVars(text: string, vars: Record<string, string>): string {
  return text.replace(/\{\{(\w+)\}\}/g, (whole, name: string) => {
    const v = vars[name];
    return v !== undefined && v !== "" ? v : whole;
  });
}

/** The `{{name}}` variable tokens present in `text`, de-duplicated. */
export function extractVarTokens(text: string): string[] {
  const seen = new Set<string>();
  for (const m of text.matchAll(/\{\{(\w+)\}\}/g)) seen.add(m[1]);
  return [...seen];
}

/** Single-brace `{placeholder}` tokens (NOT `{{vars}}`), de-duplicated —
 *  the per-request ids the operator fills inline. */
export function extractInlinePlaceholders(text: string): string[] {
  const withoutVars = text.replace(/\{\{\w+\}\}/g, "");
  const seen = new Set<string>();
  for (const m of withoutVars.matchAll(/\{(\w+)\}/g)) seen.add(m[1]);
  return [...seen];
}

/** Tokens in `text` still needing a value before it's safe to send: any
 *  `{{variable}}` whose value is unset/blank (`substituteVars` leaves those
 *  VERBATIM, so `{{siteId}}` would reach the wire), plus any leftover
 *  single-brace `{placeholder}`. A literal `{token}` in the PATH is
 *  percent-encoded by the transport, which `Endpoint::confine` refuses (no
 *  `%` in the path) with a confusing "escapes the API base" error — so the
 *  pane blocks Send on these with a clear message instead. De-duplicated. */
export function unfilledTokens(text: string, vars: Record<string, string>): string[] {
  const seen = new Set<string>();
  for (const t of extractVarTokens(text)) {
    if (!(vars[t] ?? "").trim()) seen.add(t);
  }
  for (const p of extractInlinePlaceholders(text)) seen.add(p);
  return [...seen];
}
