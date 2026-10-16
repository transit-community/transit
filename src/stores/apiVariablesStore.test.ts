import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  extractInlinePlaceholders,
  extractVarTokens,
  isSensitiveVarName,
  loadPersistedVariables,
  mergeVars,
  substituteVars,
  unfilledTokens,
  useApiVariablesStore,
} from "./apiVariablesStore";

describe("substituteVars", () => {
  it("replaces {{name}} tokens from the map", () => {
    expect(substituteVars("/v1/connector/consoles/{{consoleId}}/proxy", { consoleId: "ABC" })).toBe(
      "/v1/connector/consoles/ABC/proxy",
    );
  });

  it("leaves an unset or empty variable token verbatim (never a wrong URL)", () => {
    expect(substituteVars("/x/{{consoleId}}/y", {})).toBe("/x/{{consoleId}}/y");
    expect(substituteVars("/x/{{consoleId}}/y", { consoleId: "" })).toBe("/x/{{consoleId}}/y");
  });

  it("does NOT touch single-brace {placeholder} (per-request inline)", () => {
    expect(substituteVars("/sites/{siteId}/devices", { siteId: "s1" })).toBe(
      "/sites/{siteId}/devices",
    );
  });
});

describe("token extraction", () => {
  it("extractVarTokens finds unique {{vars}}", () => {
    expect(extractVarTokens("/{{consoleId}}/a/{{consoleId}}/{{siteId}}")).toEqual([
      "consoleId",
      "siteId",
    ]);
  });

  it("extractInlinePlaceholders finds single-brace {ids}, ignoring {{vars}}", () => {
    expect(extractInlinePlaceholders("/{{consoleId}}/sites/{siteId}/devices/{deviceId}")).toEqual([
      "siteId",
      "deviceId",
    ]);
  });
});

describe("unfilledTokens (the pre-send guard)", () => {
  it("flags a {{variable}} with no value", () => {
    expect(unfilledTokens("/sites/{{siteId}}/devices", {})).toEqual(["siteId"]);
  });

  it("passes once every {{variable}} has a value", () => {
    expect(
      unfilledTokens("/consoles/{{consoleId}}/sites/{{siteId}}", {
        consoleId: "C1",
        siteId: "S1",
      }),
    ).toEqual([]);
  });

  it("flags only the still-empty variable (consoleId set, siteId not)", () => {
    expect(
      unfilledTokens("/consoles/{{consoleId}}/sites/{{siteId}}/devices", { consoleId: "C1" }),
    ).toEqual(["siteId"]);
  });

  it("treats a whitespace-only value as unfilled", () => {
    expect(unfilledTokens("/sites/{{siteId}}", { siteId: "   " })).toEqual(["siteId"]);
  });

  it("also flags a leftover single-brace {placeholder}", () => {
    expect(unfilledTokens("/sites/{siteId}/devices", {})).toEqual(["siteId"]);
  });

  it("returns nothing for a path with no tokens", () => {
    expect(unfilledTokens("/v1/hosts", { consoleId: "C1" })).toEqual([]);
  });
});

describe("useApiVariablesStore", () => {
  beforeEach(() => {
    localStorage.clear();
    return import("vitest").then(({ vi }) => vi.resetModules());
  });
  afterEach(() => localStorage.clear());

  it("setVariable stores per api_session and persists to localStorage", async () => {
    const { useApiVariablesStore } = await import("./apiVariablesStore");
    const s = () => useApiVariablesStore.getState();
    s().setVariable("ctrl-1", "consoleId", "ABC-123");
    expect(s().variables["ctrl-1"].consoleId).toBe("ABC-123");
    // A different controller keeps its own values.
    s().setVariable("ctrl-2", "consoleId", "ZZZ-999");
    expect(s().variables["ctrl-1"].consoleId).toBe("ABC-123");
    expect(s().variables["ctrl-2"].consoleId).toBe("ZZZ-999");
    // Persisted.
    expect(JSON.parse(localStorage.getItem("transit.apiVariables")!)["ctrl-1"].consoleId).toBe(
      "ABC-123",
    );
  });

  it("setCapturedVariable holds a token in memory but NEVER persists it (T40)", async () => {
    const { useApiVariablesStore } = await import("./apiVariablesStore");
    const s = () => useApiVariablesStore.getState();
    s().setCapturedVariable("ctrl-1", "apicToken", "SESSION-TOKEN");
    // Available in memory for substitution this session…
    expect(s().captured["ctrl-1"].apicToken).toBe("SESSION-TOKEN");
    // …but the credential must NOT touch localStorage.
    expect(localStorage.getItem("transit.apiVariables")).toBeNull();
    // A persisted user var alongside it still persists — only captured is exempt.
    s().setVariable("ctrl-1", "siteId", "S1");
    const saved = JSON.parse(localStorage.getItem("transit.apiVariables")!);
    expect(saved["ctrl-1"].siteId).toBe("S1");
    expect(saved["ctrl-1"].apicToken).toBeUndefined();
  });
});

describe("mergeVars", () => {
  it("merges user vars + captured, captured winning (fresh token beats stale)", () => {
    expect(mergeVars({ siteId: "S1", token: "old" }, { token: "fresh" })).toEqual({
      siteId: "S1",
      token: "fresh",
    });
  });

  it("tolerates undefined maps", () => {
    expect(mergeVars(undefined, { token: "t" })).toEqual({ token: "t" });
    expect(mergeVars({ a: "1" }, undefined)).toEqual({ a: "1" });
    expect(mergeVars()).toEqual({});
  });
});

describe("credential-shaped variables never persist (v4.3.0)", () => {
  const SID = "ctrl-1";

  beforeEach(() => {
    localStorage.clear();
    useApiVariablesStore.setState({ variables: {}, captured: {} });
  });

  it("classifies credential names, and only those", () => {
    for (const n of ["password", "Password", "passwd", "pwd", "client_secret", "credential"]) {
      expect(isSensitiveVarName(n), n).toBe(true);
    }
    // Ids are not credentials; `token`/`apiKey` are deliberately excluded —
    // captured tokens are already in-memory, and an API key belongs in the
    // session's keychain-backed auth scheme, not a variable.
    for (const n of ["organizationId", "networkId", "consoleId", "serial", "apicToken", "apiKey"]) {
      expect(isSensitiveVarName(n), n).toBe(false);
    }
  });

  it("routes a credential to the in-memory layer, never localStorage", () => {
    const { setVariable } = useApiVariablesStore.getState();
    setVariable(SID, "password", "hunter2");
    setVariable(SID, "organizationId", "6699");

    const s = useApiVariablesStore.getState();
    expect(s.captured[SID]?.password).toBe("hunter2");
    expect(s.variables[SID]?.password).toBeUndefined();
    // the non-secret id still persists as before
    expect(s.variables[SID]?.organizationId).toBe("6699");
    expect(localStorage.getItem("transit.apiVariables") ?? "").not.toContain("hunter2");
    expect(localStorage.getItem("transit.apiVariables") ?? "").toContain("6699");
  });

  it("still substitutes a credential into the request (merged view)", () => {
    const { setVariable } = useApiVariablesStore.getState();
    setVariable(SID, "username", "admin");
    setVariable(SID, "password", "hunter2");
    const s = useApiVariablesStore.getState();
    const vars = mergeVars(s.variables[SID], s.captured[SID]);
    expect(substituteVars('{"name":"{{username}}","pwd":"{{password}}"}', vars)).toBe(
      '{"name":"admin","pwd":"hunter2"}',
    );
    expect(unfilledTokens("{{username}}{{password}}", vars)).toEqual([]);
  });

  it("purges a credential a previous build had already persisted", () => {
    localStorage.setItem(
      "transit.apiVariables",
      JSON.stringify({ [SID]: { password: "leaked", organizationId: "6699" } }),
    );
    // re-create the store from disk the way a fresh launch does
    const reloaded = loadPersistedVariables();
    expect(reloaded[SID]?.password).toBeUndefined();
    expect(reloaded[SID]?.organizationId).toBe("6699");
    // …and the purge must reach DISK, not just the returned object —
    // `setVariable` never rewrites storage for a credential-shaped name.
    const onDisk = localStorage.getItem("transit.apiVariables") ?? "";
    expect(onDisk).not.toContain("leaked");
    expect(onDisk).toContain("6699");
  });

  it("does not sweep in ordinary words that merely contain `pass`", () => {
    for (const n of ["bypass", "passive", "passthrough", "passRate", "compass"]) {
      expect(isSensitiveVarName(n), n).toBe(false);
    }
    for (const n of ["psk", "otp", "wifi_psk", "clientSecret", "j_password", "privkey"]) {
      expect(isSensitiveVarName(n), n).toBe(true);
    }
  });
});
