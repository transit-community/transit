import { useEffect, useState, type ChangeEvent, type ReactNode } from "react";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, type FieldErrors } from "react-hook-form";
import { FolderTree, KeyRound, Palette, Server, type LucideIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DeviceColorPicker } from "@/components/dialogs/DeviceColorPicker";
import type { ApiSessionInput, ApiSessionMeta, AuthSchemeWire, SecretRefInput } from "@/lib/api";
import { useAddApiSession, useEnrollApiSessionSecret, useUpdateApiSession } from "@/lib/mutations";
import {
  API_AUTH_SCHEMES,
  API_ENDPOINT_KINDS,
  API_SECRET_BACKENDS,
  API_VENDOR_OPTIONS,
  apiSessionFormSchema,
  type ApiSessionFormValues,
} from "@/lib/schemas";
import { cn } from "@/lib/utils";

// text-foreground is load-bearing on a NATIVE <select>: WebKitGTK does not
// reliably cascade the body color into form controls, so without it the
// control renders the UA color against our bg-background (white-on-white in
// light, near-black-on-black in dark). Every native select needs it.
const SELECT_CLASS =
  "flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

const FORM_ID = "api-session-form";

type ApiSectionId = "connection" | "auth" | "organization" | "appearance";

/** Left-nav rail sections (mirrors `EditDeviceDialog`'s tabbed shell, v4.2.0). */
const API_SECTIONS: { id: ApiSectionId; label: string }[] = [
  { id: "connection", label: "Connection" },
  { id: "auth", label: "Authentication" },
  { id: "organization", label: "Organization" },
  { id: "appearance", label: "Appearance" },
];

const API_SECTION_ICON: Record<ApiSectionId, LucideIcon> = {
  connection: Server,
  auth: KeyRound,
  organization: FolderTree,
  appearance: Palette,
};

/**
 * Which rail section owns each form field — so a validation error in a
 * lazy-mounted pane can't hide: `onInvalid` jumps the rail to the first
 * errored field's section (in this declaration order).
 */
const API_SECTION_FOR_FIELD: Partial<Record<keyof ApiSessionFormValues, ApiSectionId>> = {
  id: "connection",
  name: "connection",
  vendor: "connection",
  kind: "connection",
  base_url: "connection",
  host: "connection",
  console_id: "connection",
  auth_scheme: "auth",
  auth_header: "auth",
  auth_value_prefix: "auth",
  auth_username: "auth",
  backend: "auth",
  secret_value: "auth",
  op_reference: "auth",
  env_var: "auth",
  group: "organization",
  color: "appearance",
};

const RAIL_TRIGGER_CLASSES = "w-full justify-start";
const PANE_CLASSES = "mt-0 min-w-0 flex-1 overflow-y-auto pr-1";

/**
 * v4.3.0 — first-class bundled REST vendors. Each is a base-URL controller
 * (kind=generic) that ships a curated collection (see `bundledCollectionFor`)
 * plus an auth preset applied when the vendor is picked. Meraki uses a static
 * Bearer key (so the investigation-only AI agent can drive it too); the
 * login-flow vendors default to `none` — the human runs the collection's
 * "Log in first" request, captures the token into a variable, and the
 * collection's requests carry it. UniFi is intentionally NOT here (it keeps
 * its multi-surface kinds + fixed X-API-KEY).
 */
type ApiAuthScheme = "api_key" | "bearer" | "basic" | "login_credentials" | "none";
const VENDOR_PRESETS: Record<
  string,
  {
    base_url?: string;
    auth_scheme: ApiAuthScheme;
    auth_header?: string;
    auth_value_prefix?: string;
  }
> = {
  meraki: { base_url: "https://api.meraki.com/api/v1", auth_scheme: "bearer" },
  apstra: { auth_scheme: "login_credentials" },
  aruba: { auth_scheme: "login_credentials" },
  aci: { auth_scheme: "login_credentials" },
  sdwan: { auth_scheme: "login_credentials" },
  fortimanager: { auth_scheme: "login_credentials" },
  fortianalyzer: { auth_scheme: "login_credentials" },
  // v6.2.0 — NetBox classic API tokens ride `Authorization: Token <key>`
  // (the trailing space in the prefix is load-bearing). v2 `nbt_…` tokens
  // (NetBox 4.4+) are plain Bearer — the login hint says so.
  netbox: {
    auth_scheme: "api_key",
    auth_header: "Authorization",
    auth_value_prefix: "Token ",
  },
};
/** Vendors that use the generic base-URL + auth-picker shape (vs UniFi's kinds). */
const BASE_URL_VENDORS = new Set<string>(["generic", ...Object.keys(VENDOR_PRESETS)]);
/** Login-flow guidance shown in the Auth tab for vendors that authenticate at
 *  runtime (human logs in + captures a token) instead of with a stored key. */
const VENDOR_LOGIN_HINT: Record<string, string> = {
  apstra:
    "Login flow: the credentials below fill {{username}}/{{password}}, run “Log in first”, and the API token is captured into {{apstraToken}} automatically. The other requests send it as the AuthToken header.",
  aruba:
    "Login flow: the credentials below fill {{username}}/{{password}} on “Log in first”; the OAuth access token is captured into {{arubaToken}} and sent as a Bearer header. The client_id/client_secret of the token exchange are still entered per session. (For the AI agent, use Bearer with a long-lived key — a runtime token isn’t visible to it.)",
  aci: "Login flow: the credentials below fill {{username}}/{{password}}, run “Log in first” (aaaLogin), and the token is captured into {{apicToken}} automatically. The other requests send it as the APIC-cookie.",
  sdwan:
    "Login flow: the credentials below fill {{username}}/{{password}}, run “Log in first” (j_security_check), and JSESSIONID is captured into {{jsessionid}} automatically. The other requests carry it as a cookie.",
  fortimanager:
    "JSON-RPC login: the credentials below fill {{username}}/{{password}} on “Log in first”, and the session id is captured into {{fmg_session}}. These are human-only — the AI agent is GET-only and FortiManager is JSON-RPC (POST).",
  fortianalyzer:
    "JSON-RPC login: the credentials below fill {{username}}/{{password}} on “Log in first”, and the session id is captured into {{fmg_session}}. These are human-only — the AI agent is GET-only and FortiAnalyzer is JSON-RPC (POST).",
  netbox:
    "Create a token in NetBox under Profile → API Tokens. Classic tokens are sent as “Authorization: Token <key>” (the preset below — the trailing space in the prefix matters). NetBox 4.4+ v2 tokens (nbt_…) use Bearer instead: switch Auth to “Bearer token” for those.",
};

export interface AddApiSessionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Present → edit that controller; absent → add a new one. */
  session?: ApiSessionMeta;
}

function buildDefaults(session?: ApiSessionMeta): ApiSessionFormValues {
  const backend =
    (["keyring", "op", "env"] as const).find((b) => b === session?.backend) ?? "keyring";
  const auth = session?.auth;
  return {
    id: session?.id ?? "",
    name: session?.name ?? "",
    vendor: session?.vendor ?? "unifi",
    kind: session?.kind ?? "site_manager",
    host: session?.host ?? "",
    console_id: session?.console_id ?? "",
    base_url: session?.base_url ?? "",
    group: session?.group ?? "",
    color: session?.color ?? "",
    tags: session?.tags ?? [],
    auth_scheme: auth?.scheme ?? "api_key",
    auth_header: auth?.scheme === "api_key" ? auth.header : "X-API-KEY",
    auth_value_prefix: auth?.scheme === "api_key" ? (auth.value_prefix ?? "") : "",
    auth_username:
      auth?.scheme === "basic" || auth?.scheme === "login_credentials" ? auth.username : "",
    backend,
    op_reference: "",
    env_var: "",
    secret_value: "",
  };
}

function Field({ label, error, children }: { label: string; error?: string; children: ReactNode }) {
  return (
    <div className="grid gap-1">
      <label className="text-sm font-medium">{label}</label>
      {children}
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Add / edit an API controller (`[[api_session]]`). On ADD the secret is
 * stored as a reference and (keyring) the key value is enrolled write-only.
 * On EDIT the key is editable on any backend: the backend never returns a
 * SecretRef, so the form starts blank and a blank reference/value means
 * "keep the current key" (`secret: null`); a new value/reference replaces
 * it (`Some(ref)`), and switching the backend kind requires a new one.
 * Keyring values are (re-)enrolled write-only; op/env just store the
 * reference to their external store.
 */
export function AddApiSessionDialog({ open, onOpenChange, session }: AddApiSessionDialogProps) {
  const mode = session ? "edit" : "add";
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [section, setSection] = useState<ApiSectionId>("connection");

  const form = useForm<ApiSessionFormValues>({
    resolver: zodResolver(apiSessionFormSchema),
    defaultValues: buildDefaults(session),
  });

  useEffect(() => {
    if (open) form.reset(buildDefaults(session));
  }, [open, session, form]);

  const addMutation = useAddApiSession();
  const updateMutation = useUpdateApiSession();
  const enrollMutation = useEnrollApiSessionSecret();
  const pending = addMutation.isPending || updateMutation.isPending || enrollMutation.isPending;

  const vendor = form.watch("vendor");
  const usesBaseUrl = BASE_URL_VENDORS.has(vendor);
  const kind = form.watch("kind");
  const backend = form.watch("backend");
  const authScheme = form.watch("auth_scheme");
  const baseUrl = form.watch("base_url");
  const errors = form.formState.errors;
  // Generic controllers may authenticate with `none` (no secret); UniFi always
  // uses its X-API-KEY, so its secret fields always show.
  const showSecretFields = !usesBaseUrl || authScheme !== "none";
  // The credential's noun follows the scheme: password for Basic, token for
  // Bearer, else API key.
  const credentialLabel =
    !usesBaseUrl || authScheme === "api_key"
      ? "API key"
      : authScheme === "bearer"
        ? "Bearer token"
        : "Password";

  // Reveal a stranded validation error by jumping the rail to the section
  // that owns the first errored field.
  const onInvalid = (formErrors: FieldErrors<ApiSessionFormValues>) => {
    const first = (Object.keys(API_SECTION_FOR_FIELD) as (keyof ApiSessionFormValues)[]).find(
      (f) => formErrors[f],
    );
    if (first) setSection(API_SECTION_FOR_FIELD[first]!);
  };

  const onSubmit = (values: ApiSessionFormValues) => {
    setSubmitError(null);
    // A base-URL vendor (generic + the bundled REST vendors) pins kind=generic
    // + a base URL and uses the auth picker; UniFi keeps its fixed X-API-KEY
    // scheme (no auth picker shown).
    const usesBaseUrl = BASE_URL_VENDORS.has(values.vendor);
    const effectiveKind = usesBaseUrl ? "generic" : values.kind;
    const auth: AuthSchemeWire = !usesBaseUrl
      ? { scheme: "api_key", header: "X-API-KEY" }
      : values.auth_scheme === "none"
        ? { scheme: "none" }
        : values.auth_scheme === "bearer"
          ? { scheme: "bearer" }
          : values.auth_scheme === "basic"
            ? { scheme: "basic", username: values.auth_username.trim() }
            : values.auth_scheme === "login_credentials"
              ? { scheme: "login_credentials", username: values.auth_username.trim() }
              : {
                  scheme: "api_key",
                  header: values.auth_header.trim() || "X-API-KEY",
                  // Deliberately NOT trimmed — "Token " needs its trailing
                  // space to produce `Authorization: Token <key>`.
                  value_prefix: values.auth_value_prefix,
                };
    const base: Omit<ApiSessionInput, "secret"> = {
      id: values.id,
      name: values.name,
      vendor: values.vendor,
      kind: effectiveKind,
      host: effectiveKind === "network_local" ? values.host.trim() : null,
      console_id: effectiveKind === "connector_proxy" ? values.console_id.trim() : null,
      base_url: effectiveKind === "generic" ? values.base_url.trim() : null,
      group: values.group.trim() === "" ? null : values.group.trim(),
      color: values.color.trim() === "" ? null : values.color,
      tags: values.tags,
      auth,
    };

    // Resolve the secret to persist. The backend accepts Some(ref) =
    // replace, or null = keep the existing ref (edit only, since the
    // backend never hands a SecretRef back for the form to resend). A new
    // secret is REQUIRED on add, or on edit when the backend kind is
    // switched; otherwise a blank reference/value means "keep current".
    const idForKey = session?.id ?? values.id;
    // `none` auth carries no secret; every branch is gated on needsSecret so a
    // stale value left in a hidden field can't leak into a public-API session.
    const needsSecret = auth.scheme !== "none";
    const requireSecret = needsSecret && (mode === "add" || values.backend !== session?.backend);
    let secretToSend: SecretRefInput | null = null; // null = keep existing / no-auth
    let enrollValue: string | null = null;

    if (needsSecret && values.backend === "op") {
      const ref = values.op_reference.trim();
      if (requireSecret && ref === "") {
        form.setError("op_reference", { message: "Enter a 1Password reference." });
        return;
      }
      if (ref !== "") secretToSend = { backend: "op", reference: ref };
    } else if (needsSecret && values.backend === "env") {
      const v = values.env_var.trim();
      if (requireSecret && v === "") {
        form.setError("env_var", { message: "Enter an environment variable name." });
        return;
      }
      if (v !== "") secretToSend = { backend: "env", var: v };
    } else if (needsSecret) {
      // keyring — the value is enrolled write-only; the ref is derived
      // from the id, so a rotate re-enrolls at the same ref.
      const val = values.secret_value.trim();
      if (requireSecret && val === "") {
        form.setError("secret_value", {
          message: "Enter the API key, or choose a 1Password / env backend.",
        });
        return;
      }
      if (val !== "") {
        secretToSend = { backend: "keyring", key: `transit/api-${idForKey}` };
        enrollValue = values.secret_value;
      }
    }

    // Enroll the keyring value (if any) after the record is written. On
    // failure the record persisted but the key didn't — surface it and
    // keep the dialog open.
    const enrollIfNeeded = async (): Promise<boolean> => {
      if (enrollValue === null) return true;
      try {
        await enrollMutation.mutateAsync({ apiSessionId: idForKey, value: enrollValue });
        return true;
      } catch (e) {
        setSubmitError(
          `Controller saved, but setting the API key failed: ${e instanceof Error ? e.message : String(e)}`,
        );
        return false;
      }
    };

    if (mode === "edit") {
      updateMutation.mutate(
        { id: session!.id, input: { ...base, secret: secretToSend } },
        {
          onSuccess: async () => {
            if (await enrollIfNeeded()) onOpenChange(false);
          },
          onError: (e) => setSubmitError(e instanceof Error ? e.message : String(e)),
        },
      );
      return;
    }

    addMutation.mutate(
      { ...base, secret: secretToSend },
      {
        onSuccess: async () => {
          if (await enrollIfNeeded()) {
            form.reset(buildDefaults());
            onOpenChange(false);
          }
        },
        onError: (e) => setSubmitError(e instanceof Error ? e.message : String(e)),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="h-[min(34rem,85vh)] grid-rows-[auto_minmax(0,1fr)_auto] sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{mode === "edit" ? "Edit controller" : "New API controller"}</DialogTitle>
          <DialogDescription>
            A REST controller (UniFi &amp; more) you investigate via its API. The API key is stored
            by reference — the value itself is fetched from the chosen backend at request time.
          </DialogDescription>
        </DialogHeader>

        <form
          id={FORM_ID}
          onSubmit={form.handleSubmit(onSubmit, onInvalid)}
          className="flex min-h-0 min-w-0"
        >
          <Tabs
            orientation="vertical"
            value={section}
            onValueChange={(v) => setSection(v as ApiSectionId)}
            className="flex min-h-0 w-full min-w-0 gap-4"
          >
            <TabsList className="h-auto w-40 shrink-0 flex-col items-stretch gap-1 overflow-y-auto">
              {API_SECTIONS.map((s) => {
                const Icon = API_SECTION_ICON[s.id];
                return (
                  <TabsTrigger key={s.id} value={s.id} className={RAIL_TRIGGER_CLASSES}>
                    <Icon className="mr-1.5 h-3.5 w-3.5" />
                    {s.label}
                  </TabsTrigger>
                );
              })}
            </TabsList>

            <TabsContent value="connection" className={PANE_CLASSES}>
              <div className="grid gap-4">
                <Field label="ID" error={errors.id?.message}>
                  <Input
                    autoCapitalize="off"
                    autoCorrect="off"
                    spellCheck={false}
                    {...form.register("id")}
                    placeholder="office-unifi"
                    disabled={mode === "edit"}
                  />
                </Field>

                <Field label="Name" error={errors.name?.message}>
                  <Input
                    autoCapitalize="off"
                    autoCorrect="off"
                    spellCheck={false}
                    {...form.register("name")}
                    placeholder="Office UniFi"
                  />
                </Field>

                <Field label="Vendor" error={errors.vendor?.message}>
                  <select
                    className={SELECT_CLASS}
                    {...form.register("vendor", {
                      onChange: (e: ChangeEvent<HTMLSelectElement>) => {
                        // Applying a first-class vendor's preset: base URL (if
                        // fixed, e.g. Meraki) + auth scheme (+ header/prefix
                        // for header-key vendors, e.g. NetBox's
                        // `Authorization: Token <key>`). The login-flow
                        // vendors preset to `none`; the user can still switch
                        // to a static key. UniFi/generic have no preset.
                        const p = VENDOR_PRESETS[e.target.value];
                        if (!p) return;
                        if (p.base_url !== undefined)
                          form.setValue("base_url", p.base_url, { shouldDirty: true });
                        form.setValue("auth_scheme", p.auth_scheme, { shouldDirty: true });
                        if (p.auth_header !== undefined)
                          form.setValue("auth_header", p.auth_header, { shouldDirty: true });
                        if (p.auth_value_prefix !== undefined)
                          form.setValue("auth_value_prefix", p.auth_value_prefix, {
                            shouldDirty: true,
                          });
                      },
                    })}
                  >
                    {API_VENDOR_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                </Field>

                {!usesBaseUrl && (
                  <Field label="API surface" error={errors.kind?.message}>
                    <select className={SELECT_CLASS} {...form.register("kind")}>
                      {API_ENDPOINT_KINDS.filter((o) => o.value !== "generic").map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                  </Field>
                )}

                {usesBaseUrl && (
                  <Field label="Base URL" error={errors.base_url?.message}>
                    <Input
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck={false}
                      {...form.register("base_url")}
                      placeholder="https://swapi.dev/api"
                    />
                    {baseUrl.trim().toLowerCase().startsWith("http://") && (
                      <p className="text-xs text-amber-600 dark:text-amber-400" role="alert">
                        ⚠ http is unencrypted — fine for local/dev, but any credential is sent in
                        the clear. Prefer https over a network.
                      </p>
                    )}
                  </Field>
                )}

                {!usesBaseUrl && kind === "network_local" && (
                  <Field label="Controller host" error={errors.host?.message}>
                    <Input
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck={false}
                      {...form.register("host")}
                      placeholder="udm.lan:8443 or unifi.example.com:8443"
                    />
                    {/* The old copy ("Local controller", two LAN examples) read as
                        LAN-only, so MSPs hosting the Network Application on a
                        cloud VM assumed it was unsupported. Any reachable host
                        works — say so, and name the port, the other trip-up. */}
                    <p className="text-xs text-muted-foreground">
                      Host or host:port — no scheme or path. Any host this machine can reach: LAN,
                      VPN, or a cloud-hosted controller (Azure, AWS). Transit connects directly over
                      https — a self-hosted Network Application is usually <code>:8443</code>, UniFi
                      OS consoles <code>443</code>.
                    </p>
                  </Field>
                )}

                {!usesBaseUrl && kind === "connector_proxy" && (
                  <Field label="Console ID" error={errors.console_id?.message}>
                    <Input
                      autoCapitalize="off"
                      autoCorrect="off"
                      spellCheck={false}
                      {...form.register("console_id")}
                      placeholder="AAAA-BBBB-CCCC"
                    />
                  </Field>
                )}
              </div>
            </TabsContent>

            <TabsContent value="auth" className={PANE_CLASSES}>
              <div className="grid gap-4">
                {usesBaseUrl ? (
                  <>
                    <Field label="Auth" error={errors.auth_scheme?.message}>
                      <select className={SELECT_CLASS} {...form.register("auth_scheme")}>
                        {API_AUTH_SCHEMES.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    </Field>

                    {VENDOR_LOGIN_HINT[vendor] && (
                      <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-300">
                        {VENDOR_LOGIN_HINT[vendor]}
                      </p>
                    )}

                    {authScheme === "api_key" && (
                      <>
                        <Field label="Header name" error={errors.auth_header?.message}>
                          <Input
                            autoCapitalize="off"
                            autoCorrect="off"
                            spellCheck={false}
                            {...form.register("auth_header")}
                            placeholder="X-API-KEY"
                          />
                        </Field>
                        <Field
                          label="Value prefix (optional)"
                          error={errors.auth_value_prefix?.message}
                        >
                          <Input
                            autoCapitalize="off"
                            autoCorrect="off"
                            spellCheck={false}
                            {...form.register("auth_value_prefix")}
                            placeholder="Token "
                          />
                          <p className="text-xs text-muted-foreground">
                            Sent as <code>&lt;prefix&gt;&lt;key&gt;</code>: a prefix of{" "}
                            <code>Token&nbsp;</code> (trailing space included) yields NetBox&rsquo;s{" "}
                            <code>Authorization: Token &lt;key&gt;</code>. Leave blank to send the
                            bare key.
                          </p>
                        </Field>
                      </>
                    )}

                    {(authScheme === "basic" || authScheme === "login_credentials") && (
                      <Field label="Username" error={errors.auth_username?.message}>
                        <Input
                          autoCapitalize="off"
                          autoCorrect="off"
                          spellCheck={false}
                          {...form.register("auth_username")}
                          placeholder="admin"
                        />
                      </Field>
                    )}
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    UniFi controllers authenticate with the <code>X-API-KEY</code> header. Set the
                    key below.
                  </p>
                )}

                {/* Backend + credential are editable in BOTH modes. On edit, leaving
                    the reference/value blank keeps the current one; switching the
                    backend requires a new one. Hidden entirely for `none` auth. */}
                {showSecretFields ? (
                  <>
                    <Field label="Credential backend" error={errors.backend?.message}>
                      <select className={SELECT_CLASS} {...form.register("backend")}>
                        {API_SECRET_BACKENDS.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    </Field>

                    {backend === "keyring" && (
                      <Field
                        label={mode === "edit" ? `Update ${credentialLabel}` : credentialLabel}
                        error={errors.secret_value?.message}
                      >
                        <Input
                          type="password"
                          autoCapitalize="off"
                          autoCorrect="off"
                          spellCheck={false}
                          {...form.register("secret_value")}
                          placeholder={
                            mode === "edit"
                              ? "Leave blank to keep the current credential; paste a new one to rotate"
                              : "Paste the credential (stored in the OS keychain)"
                          }
                          autoComplete="off"
                        />
                      </Field>
                    )}
                    {backend === "op" && (
                      <Field label="1Password reference" error={errors.op_reference?.message}>
                        <Input
                          autoCapitalize="off"
                          autoCorrect="off"
                          spellCheck={false}
                          {...form.register("op_reference")}
                          placeholder={
                            mode === "edit"
                              ? "Leave blank to keep the current op:// reference"
                              : "op://Vault/Item/api-key"
                          }
                        />
                      </Field>
                    )}
                    {backend === "env" && (
                      <Field label="Environment variable" error={errors.env_var?.message}>
                        <Input
                          autoCapitalize="off"
                          autoCorrect="off"
                          spellCheck={false}
                          {...form.register("env_var")}
                          placeholder={
                            mode === "edit"
                              ? "Leave blank to keep the current variable"
                              : "TRANSIT_UNIFI_KEY"
                          }
                        />
                      </Field>
                    )}
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    No credential — this controller is called without authentication.
                  </p>
                )}
              </div>
            </TabsContent>

            <TabsContent value="organization" className={PANE_CLASSES}>
              <div className="grid gap-4">
                <Field label="Group (optional)" error={errors.group?.message}>
                  <Input
                    autoCapitalize="off"
                    autoCorrect="off"
                    spellCheck={false}
                    {...form.register("group")}
                    placeholder="MSP / ClientA"
                  />
                </Field>
              </div>
            </TabsContent>

            <TabsContent value="appearance" className={PANE_CLASSES}>
              <div className="grid gap-4">
                {/* #16 — accent color banner, at parity with SSH sessions. */}
                <Field label="Accent color" error={errors.color?.message}>
                  <DeviceColorPicker
                    value={form.watch("color")}
                    onChange={(v) => form.setValue("color", v, { shouldDirty: true })}
                  />
                </Field>
              </div>
            </TabsContent>
          </Tabs>
        </form>

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
            disabled={pending}
          >
            Cancel
          </Button>
          <Button type="submit" form={FORM_ID} disabled={pending}>
            {pending ? "Saving..." : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
