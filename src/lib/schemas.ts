import { z } from "zod";

/**
 * Zod schemas for inventory dialog forms. Each schema maps directly
 * to the IPC `*Input` shape on the Rust side; backend validation is
 * the source of truth (uniqueness, auth-ref resolution), but these
 * schemas catch the obvious shape errors client-side so we don't
 * round-trip to the backend just to reject "host is empty".
 */

export const VENDOR_OPTIONS = [
  { value: "junos", label: "Juniper Junos" },
  { value: "cisco_ios", label: "Cisco IOS" },
  { value: "cisco_ios_xe", label: "Cisco IOS-XE" },
  { value: "cisco_ios_xr", label: "Cisco IOS-XR" },
  { value: "nxos", label: "Cisco NX-OS" },
  { value: "arista_eos", label: "Arista EOS" },
  { value: "pan_os", label: "Palo Alto PAN-OS" },
  { value: "unifi", label: "Ubiquiti UniFi" },
  { value: "linux", label: "Linux / Unix server (unrestricted)" },
  { value: "unknown", label: "Other / unknown" },
] as const;

/**
 * Filename-safe charset for a Bring Your Own Policy custom vendor tag
 * (Phase 2b). The tag is both the inventory `vendor = "<tag>"` value and
 * the policy-file stem `<tag>.yaml`, so it's restricted to lowercase
 * letters, digits, and underscores — matching the built-in tags above
 * and the Rust loader's `vendor_from_stem` expectations. Mirrored by the
 * `deviceFormSchema.vendor` refinement and the `VendorCombobox`.
 */
export const CUSTOM_VENDOR_PATTERN = /^[a-z0-9_]+$/;

export const SUPPORTED_BACKENDS = [
  { value: "keyring", label: "OS keychain (passwords)" },
  { value: "ssh_agent", label: "SSH agent (ssh-agent, 1Password, etc.)" },
  { value: "ssh_key", label: "SSH key file" },
  { value: "op", label: "1Password CLI (op)" },
  { value: "env", label: "Environment variable" },
  // v6.1.0 — nothing is stored; the credential is typed at connect time
  // over SSH keyboard-interactive. The only backend that supports MFA /
  // OTP / PAM menus, because those need a human per attempt.
  { value: "prompt", label: "Ask me each time (interactive / MFA)" },
] as const;

export const deviceFormSchema = z.object({
  id: z
    .string()
    .min(1, "ID is required")
    .regex(/^[A-Za-z0-9_-]+$/, "letters, digits, underscore, hyphen only"),
  host: z.string().min(1, "Host is required"),
  // `z.number()` (not `z.coerce.number()`): the latter produces an
  // asymmetric input/output type (`unknown` → `number`) that the
  // newer @hookform/resolvers Resolver<Input, Context, Output>
  // signature flags as a type mismatch in `tsc -b`. The DeviceFormFields
  // input wraps `field.onChange` with `e.target.valueAsNumber` so the
  // form sees a real number, making coercion redundant anyway.
  port: z.number().int().min(1, "1-65535").max(65535, "1-65535"),
  // Built-in tags OR a custom Bring Your Own Policy vendor (Phase 2b).
  // A plain string constrained to the filename-safe charset — the
  // backend's `Vendor::from_tag` maps built-in tags to their variants
  // and any other value to `Vendor::Custom` (gated by `<value>.yaml`).
  // `z.enum` would reject custom vendors; the charset refinement keeps
  // the value usable as a policy-file stem.
  vendor: z
    .string()
    .min(1, "Vendor is required")
    .regex(CUSTOM_VENDOR_PATTERN, "lowercase letters, digits, underscores only"),
  /** Empty string → no group ("ungrouped" / root). */
  group: z.string(),
  /** Per-device accent color: a curated palette token or `#rrggbb` hex
   *  (v6.3.0), or "" for none. Empty string collapses to `null` on the
   *  wire (same pattern as `group`). DELIBERATELY an unvalidated
   *  `z.string()`: the picker constrains what can be ENTERED, but a
   *  stored value the form doesn't recognize (hand-edited transit.toml,
   *  a future build's token) must still round-trip — a refinement here
   *  made the whole edit form unsubmittable for such devices, breaking
   *  the documented graceful-fallback contract (types.rs `color` doc).
   *  Unknown values simply render with no accent. */
  color: z.string(),
  /** Free-form organizational tags (chip editor). */
  tags: z.array(z.string()),
  auth: z.string().min(1, "Auth profile is required"),
  /**
   * Per-device terminal-pane preference. The form binds it as a plain
   * boolean — defaulting is the form's job (`defaultValues`), not the
   * schema's, because zod's `.default(false)` produces an asymmetric
   * input/output type that confuses react-hook-form's resolver.
   * The dialog's submit handler converts `false` → `null` on the wire
   * so the TOML stays clean for users who never touched the checkbox.
   */
  syntax_highlighting: z.boolean(),
  /** SecureCRT-style quick copy/paste — same null-on-false semantics. */
  quick_copy_paste: z.boolean(),
  /** Per-device terminal font family override; "" = use the global
   *  terminal font. Collapses to `null` on the wire (like `color`). */
  font_family: z.string(),
  /** Per-device terminal font size in CSS pixels; 0 = use the global
   *  size, 8–32 otherwise. Collapses to `null` on the wire. */
  font_size: z
    .number()
    .int()
    .refine((n) => n === 0 || (n >= 8 && n <= 32), "8–32, or 0 for the global default"),
  /** Per-device "bold accent" — render the color as a louder background
   *  tint. `false` → `null` on the wire, same as the other prefs. */
  bold_color: z.boolean(),
  /** Jump host (v6.5.0): the id of another device to tunnel through;
   *  "" = direct connection, collapsed to `null` on the wire.
   *  DELIBERATELY an unvalidated `z.string()` (the `color` lesson): the
   *  picker constrains what can be ENTERED, but a reference the form
   *  can't resolve (hand-edited transit.toml) must keep the form
   *  submittable — the BACKEND loader/mutator owns referential
   *  validation (existence, self-reference, cycles, depth). */
  jump_via: z.string(),
  /** Per-device SSH agent-forwarding opt-in (v6.5.0, T53). Plain
   *  boolean like the other toggles; `false` → `null` on the wire. */
  forward_agent: z.boolean(),
});

export type DeviceFormValues = z.infer<typeof deviceFormSchema>;

// ---------------------------------------------------------------------
// v4.0.0 — API sessions (UniFi & other REST controllers).
// ---------------------------------------------------------------------

/** API vendors. `unifi` ships a bundled collection + kinds; `generic` is a
 *  user-defined controller (any base URL, no bundled collection). */
export const API_VENDOR_OPTIONS = [
  { value: "unifi", label: "UniFi (Ubiquiti)" },
  // v4.3.0 — bundled first-class REST vendors: base-URL controllers that ship a
  // curated investigation collection + an auth preset (VENDOR_PRESETS in
  // AddApiSessionDialog; collection in bundledCollectionFor). All are
  // Vendor::Custom backend-side (the vendor field is a free string).
  { value: "meraki", label: "Cisco Meraki" },
  { value: "apstra", label: "Juniper Apstra" },
  { value: "aruba", label: "HPE Aruba Central" },
  { value: "aci", label: "Cisco ACI (APIC)" },
  { value: "sdwan", label: "Cisco Catalyst SD-WAN" },
  { value: "fortimanager", label: "FortiManager" },
  { value: "fortianalyzer", label: "FortiAnalyzer" },
  // v6.2.0 — NetBox (CMDB/IPAM): the first bundled collection whose target
  // is a source of truth about devices rather than a controller of them.
  { value: "netbox", label: "NetBox" },
  { value: "generic", label: "Generic / Custom API" },
] as const;

/** Which API surface + how it's reached (mirrors Rust `ApiEndpointKind`). */
export const API_ENDPOINT_KINDS = [
  { value: "site_manager", label: "Site Manager — cloud (api.ui.com)" },
  // "Self-hosted", NOT "local": the distinction between the three UniFi
  // surfaces is whether traffic is relayed through api.ui.com, not whether the
  // controller is on-link. An MSP running the Network Application on a cloud VM
  // (Azure/AWS) belongs here, and "Local" led them to think it was unsupported.
  { value: "network_local", label: "Self-hosted controller — Network API" },
  { value: "connector_proxy", label: "Cloud connector-proxy (per console)" },
  { value: "generic", label: "Custom — any base URL" },
] as const;

/** How a controller authenticates (mirrors Rust `AuthScheme`). */
export const API_AUTH_SCHEMES = [
  { value: "api_key", label: "API key (custom header)" },
  { value: "bearer", label: "Bearer token" },
  { value: "basic", label: "Basic (username + password)" },
  { value: "login_credentials", label: "Login credentials (sent by the login request)" },
  { value: "none", label: "No auth (public API)" },
] as const;

/** Secret backends that fit a plain-string API key. */
export const API_SECRET_BACKENDS = [
  { value: "keyring", label: "OS keychain" },
  { value: "op", label: "1Password CLI (op)" },
  { value: "env", label: "Environment variable" },
  // v6.1.0 — nothing is stored; the credential is typed at connect time
  // over SSH keyboard-interactive. The only backend that supports MFA /
  // OTP / PAM menus, because those need a human per attempt.
  { value: "prompt", label: "Ask me each time (interactive / MFA)" },
] as const;

export const apiSessionFormSchema = z
  .object({
    id: z
      .string()
      .min(1, "ID is required")
      .regex(/^[A-Za-z0-9_-]+$/, "letters, digits, underscore, hyphen only"),
    name: z.string().min(1, "Name is required"),
    vendor: z.string().min(1, "Vendor is required"),
    kind: z.enum(["site_manager", "network_local", "connector_proxy", "generic"]),
    /** Required iff kind === network_local (host or host:port, no scheme). */
    host: z.string(),
    /** Required iff kind === connector_proxy. */
    console_id: z.string(),
    /** Full base URL — required iff kind === generic (https, or http w/ warning). */
    base_url: z.string(),
    group: z.string(),
    /** Same deliberate non-validation as `deviceFormSchema.color`. */
    color: z.string(),
    tags: z.array(z.string()),
    /** How the controller authenticates. */
    auth_scheme: z.enum(["api_key", "bearer", "basic", "login_credentials", "none"]),
    /** Header name for the api_key scheme (default X-API-KEY). */
    auth_header: z.string(),
    /** Non-secret text prepended to the key in the header value (api_key
     *  scheme only) — "Token " yields NetBox's `Authorization: Token <key>`.
     *  Blank = the bare key (the historic shape). */
    auth_value_prefix: z.string(),
    /** Username for the basic + login_credentials schemes. */
    auth_username: z.string(),
    /** Secret backend — how the credential is fetched (unused for `none`). */
    backend: z.enum(["keyring", "op", "env"]),
    /** op:// reference (op backend). */
    op_reference: z.string(),
    /** Env var name (env backend). */
    env_var: z.string(),
    /** The actual API key value — enrolled to the keychain on add
     *  (keyring backend only). Blank = don't enroll now. */
    secret_value: z.string(),
  })
  .superRefine((v, ctx) => {
    if (v.kind === "network_local" && v.host.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["host"],
        message: "Host is required for a self-hosted controller",
      });
    }
    if (v.kind === "connector_proxy" && v.console_id.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["console_id"],
        message: "Console ID is required for the connector-proxy",
      });
    }
    if (v.kind === "generic" && v.base_url.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["base_url"],
        message: "Base URL is required for a generic controller",
      });
    }
    if (
      (v.auth_scheme === "basic" || v.auth_scheme === "login_credentials") &&
      v.auth_username.trim() === ""
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["auth_username"],
        message: "Username is required",
      });
    }
    // `none` needs no credential, so skip the secret-backend checks for it.
    if (v.auth_scheme !== "none" && v.backend === "op" && v.op_reference.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["op_reference"],
        message: "op:// reference is required",
      });
    }
    if (v.auth_scheme !== "none" && v.backend === "env" && v.env_var.trim() === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["env_var"],
        message: "Environment variable name is required",
      });
    }
  });

export type ApiSessionFormValues = z.infer<typeof apiSessionFormSchema>;

export const authProfileFormSchema = z
  .object({
    /** Used only when creating; ignored on edit (caller passes the
     *  existing name through). */
    name: z
      .string()
      .min(1, "Name is required")
      .regex(/^[a-z0-9_-]+$/, "lowercase letters, digits, underscore, hyphen only"),
    username: z.string().min(1, "Username is required"),
    backend: z.enum(["keyring", "ssh_agent", "ssh_key", "op", "env", "prompt"]),
    /** Backend-specific reference body. Conditionally validated below. */
    keyring_key: z.string().optional(),
    ssh_agent_fingerprint: z.string().optional(),
    /** Absolute path to the on-disk private key (ssh_key backend). */
    ssh_key_path: z.string().optional(),
    /** The key's passphrase, if encrypted. Enrolled to the keychain on
     *  save (never stored in the inventory). Blank = unencrypted key. */
    ssh_key_passphrase: z.string().optional(),
    op_reference: z.string().optional(),
    env_var: z.string().optional(),
    /** Phase 7a C14 — the actual secret value, only relevant for the
     *  keyring backend. Blank means "don't enroll on save". On submit
     *  the dialog calls `enrollSecret(name, value)` after the profile
     *  upsert succeeds. */
    secret_value: z.string().optional(),
  })
  .superRefine((v, ctx) => {
    switch (v.backend) {
      case "keyring":
        if (!v.keyring_key || v.keyring_key.trim() === "") {
          ctx.addIssue({
            code: "custom",
            path: ["keyring_key"],
            message: "Keyring key is required",
          });
        }
        break;
      case "op":
        if (!v.op_reference || !/^op:\/\//.test(v.op_reference.trim())) {
          ctx.addIssue({
            code: "custom",
            path: ["op_reference"],
            message: "Must be an op:// reference",
          });
        }
        break;
      case "env":
        if (!v.env_var || !/^[A-Z][A-Z0-9_]*$/.test(v.env_var.trim())) {
          ctx.addIssue({
            code: "custom",
            path: ["env_var"],
            message: "Must be an UPPER_SNAKE env var name",
          });
        }
        break;
      case "ssh_key":
        if (!v.ssh_key_path || v.ssh_key_path.trim() === "") {
          ctx.addIssue({
            code: "custom",
            path: ["ssh_key_path"],
            message: "Choose a private key file",
          });
        }
        break;
      // ssh_agent's fingerprint is optional — no extra validation.
      // `prompt` has NOTHING to validate by design: no key, no path, no
      // reference, and nothing to enroll. Any secret typed into the form
      // is ignored on submit (see AuthProfileDialog) — the credential
      // only ever arrives through the connect-time dialog.
    }
  });

export type AuthProfileFormValues = z.infer<typeof authProfileFormSchema>;

/**
 * A group path field: non-empty, no leading/trailing slash, and no
 * empty interior segment (`A//B`). Mirrors the backend
 * `validate_group_path` so the dialog rejects the same inputs the
 * mutator would. Reused by the rename and add-group forms.
 */
export const groupPathSchema = z
  .string()
  .min(1, "Group path is required")
  .refine((s) => !s.startsWith("/") && !s.endsWith("/"), {
    message: "Don't include leading or trailing slashes",
  })
  .refine((s) => !s.split("/").some((seg) => seg.trim() === ""), {
    message: "Group names can't be empty (no '//' or blank segments)",
  });

export const renameGroupFormSchema = z.object({
  newPath: groupPathSchema,
});

export type RenameGroupFormValues = z.infer<typeof renameGroupFormSchema>;

export const addGroupFormSchema = z.object({
  path: groupPathSchema,
});

export type AddGroupFormValues = z.infer<typeof addGroupFormSchema>;
