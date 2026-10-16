import { describe, expect, it } from "vitest";

import type { ApiSessionMeta } from "@/lib/api";
import { isDestructiveMethod, type ApiFolder } from "@/lib/apiCollections";

import { sessionAuthHeaderFor } from "./apiCollections";
import { apiBaseDisplay, bundledCollectionFor } from "./bundledCollections";

function allRequests(folder: ApiFolder): { method: string; path: string; destructive: boolean }[] {
  const out: { method: string; path: string; destructive: boolean }[] = [];
  const walk = (f: ApiFolder) => {
    for (const r of f.requests)
      out.push({ method: r.method, path: r.path, destructive: r.destructive });
    for (const sub of f.folders) walk(sub);
  };
  walk(folder);
  return out;
}

/** Like `allRequests` but keeps the whole request — body, headers, capture. */
function fullRequests(folder: ApiFolder): ApiFolder["requests"] {
  const out: ApiFolder["requests"] = [];
  const walk = (f: ApiFolder) => {
    out.push(...f.requests);
    for (const sub of f.folders) walk(sub);
  };
  walk(folder);
  return out;
}

describe("bundledCollectionFor", () => {
  it("maps UniFi surfaces to their catalogs", () => {
    // Cloud controller = the unified three-surface catalog.
    expect(bundledCollectionFor("unifi", "site_manager")?.id).toBe("unifi-cloud");
    // A direct/proxied Network base = the Network-only catalog.
    expect(bundledCollectionFor("unifi", "network_local")?.id).toBe("unifi-network");
    expect(bundledCollectionFor("unifi", "connector_proxy")?.id).toBe("unifi-network");
  });

  it("the cloud collection groups Site Manager / Network / Protect as folders", () => {
    const c = bundledCollectionFor("unifi", "site_manager")!;
    expect(c.root.folders.map((f) => f.name)).toEqual([
      "Site Manager",
      "Network (via connector)",
      "Protect (via connector)",
    ]);
    // Network + Protect reach the console through the cloud connector proxy.
    // (Network requests nest in subfolders, so walk recursively.)
    const net = allRequests(c.root.folders.find((f) => f.name.startsWith("Network"))!);
    expect(net.length).toBeGreaterThan(50); // the full generated official set
    expect(
      net.every((r) => r.path.includes("/connector/consoles/{{consoleId}}/proxy/network/")),
    ).toBe(true);
    const prot = allRequests(c.root.folders.find((f) => f.name.startsWith("Protect"))!);
    expect(
      prot.every((r) => r.path.includes("/connector/consoles/{{consoleId}}/proxy/protect/")),
    ).toBe(true);
  });

  it("returns null for an unregistered vendor", () => {
    // "fortinet" is NOT a registered tag (the Forti collections ship as
    // "fortimanager" / "fortianalyzer"); a wholly unknown vendor is null too.
    expect(bundledCollectionFor("fortinet", "generic")).toBeNull();
    expect(bundledCollectionFor("custom-thing", "network_local")).toBeNull();
  });

  it("every request's destructive flag matches its method (writes flagged)", () => {
    for (const kind of ["site_manager", "network_local"] as const) {
      for (const r of allRequests(bundledCollectionFor("unifi", kind)!.root)) {
        expect(r.destructive).toBe(isDestructiveMethod(r.method));
      }
    }
  });

  it("the Network catalog includes write endpoints (POST + DELETE) for the human", () => {
    const methods = new Set(
      allRequests(bundledCollectionFor("unifi", "network_local")!.root).map((r) => r.method),
    );
    expect(methods.has("GET")).toBe(true);
    expect(methods.has("POST")).toBe(true);
    expect(methods.has("DELETE")).toBe(true);
  });

  it("every path param is a {{variable}}, never a single-brace {inline} (#15)", () => {
    // A single-brace {siteId} reaches the wire verbatim (substituteVars only
    // fills {{vars}}), gets percent-encoded, and Endpoint::confine refuses any
    // `%` in the path — surfacing as the confusing "escapes the API base"
    // error. Every bundled path param must be a settable {{variable}} so the
    // Variables bar / right-click "Set as variable" can fill it.
    const singleBrace = /(?<!\{)\{\w+\}(?!\})/;
    for (const kind of ["site_manager", "network_local"] as const) {
      for (const r of allRequests(bundledCollectionFor("unifi", kind)!.root)) {
        expect(
          singleBrace.test(r.path),
          `${r.method} ${r.path} still has a single-brace param`,
        ).toBe(false);
      }
    }
  });

  it("Site Manager paths are host-absolute; Network paths are relative", () => {
    // Site Manager base is `/`, so absolute `/v1/...` resolves under it.
    for (const r of allRequests(bundledCollectionFor("unifi", "site_manager")!.root)) {
      expect(r.path.startsWith("/")).toBe(true);
    }
    // Network base carries a prefix; RELATIVE paths keep the SAME collection
    // valid for both network_local and the deeper connector-proxy base.
    for (const r of allRequests(bundledCollectionFor("unifi", "network_local")!.root)) {
      expect(r.path.startsWith("/")).toBe(false);
    }
  });
});

describe("v4.3.0 first-class REST vendors", () => {
  const VENDORS = [
    "meraki",
    "apstra",
    "aruba",
    "aci",
    "sdwan",
    "fortimanager",
    "fortianalyzer",
    "netbox",
  ] as const;
  // The RESTful login-flow / key vendors (Fortinet is JSON-RPC, tested apart).
  const REST = ["meraki", "apstra", "aruba", "aci", "sdwan", "netbox"] as const;

  it("each vendor maps to its own non-empty bundled collection (any kind)", () => {
    for (const v of VENDORS) {
      const c = bundledCollectionFor(v, "generic");
      expect(c, v).not.toBeNull();
      expect(c!.vendor).toBe(v);
      expect(c!.bundled).toBe(true);
      expect(allRequests(c!.root).length).toBeGreaterThan(0);
    }
  });

  it("REST vendors: every destructive flag matches its HTTP method", () => {
    for (const v of REST) {
      for (const r of allRequests(bundledCollectionFor(v, "generic")!.root)) {
        expect(r.destructive, `${v} ${r.method} ${r.path}`).toBe(isDestructiveMethod(r.method));
      }
    }
  });

  it("REST vendors: any non-GET request is flagged destructive (human writes)", () => {
    // Collections now ship human writes (like UniFi). The AI agent is GET-only
    // STRUCTURALLY regardless of collection content, so a write is purely a
    // human convenience — and must be destructive-flagged so the pane confirms
    // before sending it (login POSTs included).
    for (const v of REST) {
      for (const r of allRequests(bundledCollectionFor(v, "generic")!.root)) {
        if (r.method !== "GET") {
          expect(r.destructive, `${v} ${r.method} ${r.path} must be destructive`).toBe(true);
        }
      }
    }
  });

  it("login-flow vendors carry their auth header on every investigation request", () => {
    // scheme=none sessions inject nothing server-side, so the collection must
    // carry the captured token itself (client.rs leaves a manual auth header
    // intact for `none`). Missing header ⇒ the flow silently 401s.
    const HDR: Record<string, string> = {
      apstra: "AuthToken",
      aruba: "Authorization",
      aci: "Cookie",
      sdwan: "Cookie",
    };
    for (const [v, key] of Object.entries(HDR)) {
      for (const f of bundledCollectionFor(v, "generic")!.root.folders) {
        if (f.name === "Log in first") continue;
        for (const r of f.requests) {
          expect(
            r.headers.some((h) => h.key === key),
            `${v} ${r.path} missing ${key} header`,
          ).toBe(true);
        }
      }
    }
  });

  it("Fortinet collections are JSON-RPC (POST /jsonrpc) — human-only", () => {
    // JSON-RPC is POST, so the GET-only agent structurally can never call these;
    // they're a human convenience. The op lives in the body, not the path.
    for (const v of ["fortimanager", "fortianalyzer"] as const) {
      const reqs = allRequests(bundledCollectionFor(v, "generic")!.root);
      expect(reqs.length).toBeGreaterThan(0);
      expect(
        reqs.every((r) => r.method === "POST" && r.path === "/jsonrpc"),
        v,
      ).toBe(true);
    }
  });

  it("every path param is a {{variable}}, never single-brace (#15)", () => {
    const singleBrace = /(?<!\{)\{\w+\}(?!\})/;
    for (const v of VENDORS) {
      for (const r of allRequests(bundledCollectionFor(v, "generic")!.root)) {
        expect(singleBrace.test(r.path), `${v}: ${r.path}`).toBe(false);
      }
    }
  });

  it("login-flow vendors ship a capture rule so the token auto-populates (6d)", () => {
    // "Log in first" carries a declarative capture rule → the token variable
    // fills without a manual right-click. Meraki (Bearer, no login) has none.
    const captureCount = (v: string): number => {
      let n = 0;
      const walk = (f: ApiFolder) => {
        for (const r of f.requests) if (r.capture && r.capture.length > 0) n += 1;
        for (const sf of f.folders) walk(sf);
      };
      walk(bundledCollectionFor(v, "generic")!.root);
      return n;
    };
    for (const v of ["apstra", "aruba", "aci", "sdwan", "fortimanager", "fortianalyzer"]) {
      expect(captureCount(v), `${v} has a login capture rule`).toBeGreaterThan(0);
    }
    expect(captureCount("meraki")).toBe(0);
  });

  it("login requests use the canonical {{username}}/{{password}} pair", () => {
    // One credential vocabulary across every vendor is what lets ONE rule fill
    // them from the keychain server-side and ONE rule mask anything hand-typed.
    // They previously differed per vendor (j_username, central_username, user,
    // …) and Apstra had none at all — it shipped literal "<string>"
    // placeholders and posted them verbatim.
    //
    // Asserted over the whole collection rather than per-request: Aruba's OAuth
    // is multi-step, and the step carrying the credentials is not the step that
    // captures the token.
    for (const v of ["apstra", "aruba", "aci", "sdwan", "fortimanager", "fortianalyzer"]) {
      const blob = fullRequests(bundledCollectionFor(v, "generic")!.root)
        .map((r) => (r.body ?? "") + r.headers.map((h) => h.value).join())
        .join();
      expect(blob, `${v} must reference {{username}}`).toContain("{{username}}");
      expect(blob, `${v} must reference {{password}}`).toContain("{{password}}");
      // Only the credential-bearing request matters: `<string>` is a
      // legitimate "fill this in" placeholder in a write template (Apstra
      // ships 22 of them), but in the LOGIN body it meant the operator had no
      // way to supply credentials and the literal text got POSTed.
      const loginBodies = fullRequests(bundledCollectionFor(v, "generic")!.root)
        .filter((r) => (r.body ?? "").includes("{{username}}"))
        .map((r) => r.body ?? "");
      expect(loginBodies.length, `${v} has a credential-bearing request`).toBeGreaterThan(0);
      for (const b of loginBodies) {
        expect(b, `${v} login body must not ship <string>`).not.toContain("<string>");
      }
    }
    // Meraki authenticates with a static Bearer key — no login request at all.
    const meraki = fullRequests(bundledCollectionFor("meraki", "generic")!.root)
      .map((r) => (r.body ?? "") + r.headers.map((h) => h.value).join())
      .join();
    expect(meraki).not.toContain("{{password}}");
  });

  it("every login-flow vendor resolves a session auth header for agent replay", () => {
    // The agent's GET carries no captured token unless the backend is handed
    // the header the collection uses. `sessionAuthHeaderFor` derives it from
    // the shipped requests, so a new vendor gets it for free — no per-vendor
    // table to forget. Missing header ⇒ the agent 403s on that vendor while
    // the human pane works, which is exactly the ACI bug this closes.
    const EXPECT: Record<string, { varName: string; header: string }> = {
      aci: { varName: "apicToken", header: "Cookie" },
      sdwan: { varName: "jsessionid", header: "Cookie" },
      apstra: { varName: "apstraToken", header: "AuthToken" },
      aruba: { varName: "arubaToken", header: "Authorization" },
    };
    for (const [v, { varName, header }] of Object.entries(EXPECT)) {
      const coll = bundledCollectionFor(v, "generic")!;
      const found = sessionAuthHeaderFor([coll], varName);
      expect(found, `${v}: no session auth header for {{${varName}}}`).not.toBeNull();
      expect(found!.name).toBe(header);
      expect(found!.template).toContain(`{{${varName}}}`);
    }
    // Fortinet carries its session in the JSON-RPC BODY, not a header — and
    // the GET-only agent cannot call JSON-RPC anyway, so null is correct.
    for (const v of ["fortimanager", "fortianalyzer"]) {
      const coll = bundledCollectionFor(v, "generic")!;
      expect(sessionAuthHeaderFor([coll], "fmg_session")).toBeNull();
    }
  });

  it("no bundled request puts a credential in the URL path", () => {
    // The backend refuses this outright (a credential in a path is recorded
    // into the agent-visible session ring by `record_exchange`, and into the
    // controller's access log) — so no shipped collection may rely on it.
    for (const v of [
      "meraki",
      "apstra",
      "aruba",
      "aci",
      "sdwan",
      "fortimanager",
      "fortianalyzer",
      "netbox",
    ]) {
      for (const r of fullRequests(bundledCollectionFor(v, "generic")!.root)) {
        expect(r.path, `${v}: ${r.path}`).not.toContain("{{password}}");
      }
    }
  });
});

describe("v6.2.0 NetBox collection", () => {
  // The first bundled collection whose target is a source of truth ABOUT
  // devices (CMDB/IPAM) rather than a controller OF them — read-only by
  // design, not just by agent-side structure.
  it("is GET-only and nothing is destructive", () => {
    const reqs = allRequests(bundledCollectionFor("netbox", "generic")!.root);
    expect(reqs.length).toBeGreaterThanOrEqual(25);
    for (const r of reqs) {
      expect(r.method, r.path).toBe("GET");
      expect(r.destructive, r.path).toBe(false);
    }
  });

  it("paths are relative — the documented base carries the /api prefix", () => {
    // Mirrors bundled_collections_confine.rs's shape test so a frontend-only
    // regeneration fails here without needing the Rust suite.
    for (const r of allRequests(bundledCollectionFor("netbox", "generic")!.root)) {
      expect(r.path.startsWith("/"), r.path).toBe(false);
    }
  });

  it("ships the circuit-outage pivot (terminations by circuit)", () => {
    // The ISP workflow this collection exists for: circuit → terminations →
    // site/devices. If a regeneration drops the filtered variant, fail by name.
    const paths = allRequests(bundledCollectionFor("netbox", "generic")!.root).map((r) => r.path);
    expect(paths).toContain("circuits/circuit-terminations/?circuit_id={{circuitId}}");
    expect(paths.some((p) => p.startsWith("dcim/devices/?site_id="))).toBe(true);
  });

  it("carries no bodies, no captures, no headers (pure GETs)", () => {
    for (const r of fullRequests(bundledCollectionFor("netbox", "generic")!.root)) {
      expect(r.body, r.path).toBeNull();
      expect(r.capture ?? [], r.path).toHaveLength(0);
      expect(r.headers, r.path).toHaveLength(0);
    }
  });
});

describe("apiBaseDisplay", () => {
  const base = (over: Partial<ApiSessionMeta>): ApiSessionMeta => ({
    id: "x",
    name: "X",
    vendor: "unifi",
    kind: "site_manager",
    host: null,
    console_id: null,
    base_url: null,
    group: null,
    color: null,
    tags: [],
    backend: "op",
    auth: { scheme: "api_key", header: "X-API-KEY" },
    ...over,
  });

  it("renders the fixed base per surface", () => {
    expect(apiBaseDisplay(base({ kind: "site_manager" }))).toBe("https://api.ui.com");
    expect(apiBaseDisplay(base({ kind: "network_local", host: "10.0.0.1" }))).toBe(
      "https://10.0.0.1/proxy/network/integration/v1",
    );
    expect(apiBaseDisplay(base({ kind: "connector_proxy", console_id: "AAAA-BBBB" }))).toContain(
      "consoles/AAAA-BBBB/proxy/network/integration/v1",
    );
  });
});
