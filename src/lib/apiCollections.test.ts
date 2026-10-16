import { describe, expect, it } from "vitest";

import {
  collectGetEndpoints,
  scrubCredentialsFromBody,
  importPostmanCollection,
  isDestructiveMethod,
  type ApiCollection,
  type ApiFolder,
} from "./apiCollections";

/** Deterministic id factory so tests can assert structure, not UUIDs. */
function seqIds() {
  let n = 0;
  return () => `id-${n++}`;
}

/** Flatten every request across the folder tree, depth-first. */
function allRequests(root: ApiFolder): { name: string; method: string; path: string }[] {
  const out: { name: string; method: string; path: string }[] = [];
  const walk = (f: ApiFolder) => {
    for (const r of f.requests) out.push({ name: r.name, method: r.method, path: r.path });
    for (const sub of f.folders) walk(sub);
  };
  walk(root);
  return out;
}

describe("isDestructiveMethod", () => {
  it("flags mutating verbs, not GET/HEAD/OPTIONS", () => {
    for (const m of ["POST", "put", "Patch", "DELETE"]) expect(isDestructiveMethod(m)).toBe(true);
    for (const m of ["GET", "HEAD", "OPTIONS", " get "]) expect(isDestructiveMethod(m)).toBe(false);
  });
});

describe("importPostmanCollection — happy path (v2.1)", () => {
  const collection = {
    info: {
      name: "UniFi Network",
      schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    item: [
      {
        name: "Sites",
        item: [
          {
            name: "List sites",
            request: {
              method: "GET",
              header: [],
              url: {
                raw: "https://{{host}}/proxy/network/integration/v1/sites",
                host: ["{{host}}"],
                path: ["proxy", "network", "integration", "v1", "sites"],
              },
            },
          },
          {
            name: "List devices (limit)",
            request: {
              method: "GET",
              url: {
                host: ["{{host}}"],
                path: ["proxy", "network", "integration", "v1", "devices"],
                query: [
                  { key: "limit", value: "10" },
                  { key: "offset", value: "0", disabled: true },
                ],
              },
            },
          },
        ],
      },
      {
        name: "Restart device",
        request: {
          method: "POST",
          url: {
            path: ["proxy", "network", "integration", "v1", "devices", "abc", "actions"],
          },
          body: { mode: "raw", raw: '{ "action": "RESTART" }' },
        },
      },
    ],
    variable: [{ key: "host", value: "10.0.0.1" }],
  };

  it("preserves folder structure + names", () => {
    const { collection: c } = importPostmanCollection(collection, seqIds());
    expect(c.name).toBe("UniFi Network");
    expect(c.root.folders).toHaveLength(1);
    expect(c.root.folders[0].name).toBe("Sites");
    expect(c.root.folders[0].requests.map((r) => r.name)).toEqual([
      "List sites",
      "List devices (limit)",
    ]);
    // Top-level request sits directly under root.
    expect(c.root.requests.map((r) => r.name)).toEqual(["Restart device"]);
  });

  it("builds host-absolute paths from the path array, dropping the host", () => {
    const { collection: c } = importPostmanCollection(collection, seqIds());
    const reqs = allRequests(c.root);
    expect(reqs.find((r) => r.name === "List sites")?.path).toBe(
      "/proxy/network/integration/v1/sites",
    );
  });

  it("appends only enabled query params", () => {
    const { collection: c } = importPostmanCollection(collection, seqIds());
    const dev = allRequests(c.root).find((r) => r.name === "List devices (limit)");
    expect(dev?.path).toBe("/proxy/network/integration/v1/devices?limit=10");
  });

  it("flags non-GET as destructive and keeps the raw body", () => {
    const { collection: c } = importPostmanCollection(collection, seqIds());
    const restart = c.root.requests.find((r) => r.name === "Restart device")!;
    expect(restart.method).toBe("POST");
    expect(restart.destructive).toBe(true);
    expect(restart.body).toBe('{ "action": "RESTART" }');
  });

  it("carries collection variables through", () => {
    const { collection: c } = importPostmanCollection(collection, seqIds());
    expect(c.variables).toEqual([{ key: "host", value: "10.0.0.1" }]);
  });
});

describe("importPostmanCollection — URL string forms", () => {
  it("keeps only path+query from a full URL with a templated host", () => {
    const doc = {
      info: { name: "x", schema: "v2.1.0" },
      item: [{ name: "r", request: { method: "GET", url: "https://{{host}}/v1/hosts?x=1" } }],
    };
    const { collection: c } = importPostmanCollection(doc, seqIds());
    expect(c.root.requests[0].path).toBe("/v1/hosts?x=1");
  });

  it("passes a bare absolute path through unchanged", () => {
    const doc = {
      info: { name: "x" },
      item: [{ name: "r", request: { url: "/v1/sites" } }],
    };
    const { collection: c } = importPostmanCollection(doc, seqIds());
    expect(c.root.requests[0].path).toBe("/v1/sites");
    // No method → defaults to GET, not destructive.
    expect(c.root.requests[0].method).toBe("GET");
  });

  it("strips a fragment", () => {
    const doc = {
      info: { name: "x" },
      item: [{ name: "r", request: { url: "https://api.ui.com/v1/hosts#frag" } }],
    };
    const { collection: c } = importPostmanCollection(doc, seqIds());
    expect(c.root.requests[0].path).toBe("/v1/hosts");
  });

  it("supports the shorthand where `request` is a bare URL string", () => {
    const doc = {
      info: { name: "x" },
      item: [{ name: "r", request: "https://{{host}}/v1/devices" }],
    };
    const { collection: c } = importPostmanCollection(doc, seqIds());
    expect(c.root.requests[0].method).toBe("GET");
    expect(c.root.requests[0].path).toBe("/v1/devices");
  });
});

describe("importPostmanCollection — sanitization", () => {
  it("drops disabled headers and strips X-API-KEY / Authorization with a warning", () => {
    const doc = {
      info: { name: "x" },
      item: [
        {
          name: "r",
          request: {
            method: "GET",
            url: "/v1/hosts",
            header: [
              { key: "Accept", value: "application/json" },
              { key: "X-API-KEY", value: "leaked-secret-should-not-persist" },
              { key: "Authorization", value: "Bearer nope" },
              { key: "X-Debug", value: "1", disabled: true },
            ],
          },
        },
      ],
    };
    const { collection: c, warnings } = importPostmanCollection(doc, seqIds());
    const headers = c.root.requests[0].headers;
    expect(headers).toEqual([{ key: "Accept", value: "application/json" }]);
    // The secret value must be nowhere in the imported model.
    expect(JSON.stringify(c)).not.toContain("leaked-secret-should-not-persist");
    expect(warnings.some((w) => /API key is injected/.test(w))).toBe(true);
  });

  it("reconstructs a urlencoded body and warns on unsupported modes", () => {
    const enc = {
      info: { name: "x" },
      item: [
        {
          name: "form",
          request: {
            method: "POST",
            url: "/v1/x",
            body: {
              mode: "urlencoded",
              urlencoded: [
                { key: "a", value: "1" },
                { key: "b", value: "two words" },
                { key: "c", value: "skip", disabled: true },
              ],
            },
          },
        },
      ],
    };
    const { collection: c } = importPostmanCollection(enc, seqIds());
    expect(c.root.requests[0].body).toBe("a=1&b=two%20words");

    const formdata = {
      info: { name: "x" },
      item: [
        {
          name: "file",
          request: { method: "POST", url: "/v1/x", body: { mode: "formdata", formdata: [] } },
        },
      ],
    };
    const { collection: c2, warnings } = importPostmanCollection(formdata, seqIds());
    expect(c2.root.requests[0].body).toBeNull();
    expect(warnings.some((w) => /formdata.*dropped/.test(w))).toBe(true);
  });

  it("drops the VALUE of a credential-shaped collection variable, keeping the key", () => {
    // Collection variables are persisted verbatim with the collection, and
    // `{"key":"password","value":"…"}` is the commonest way a Postman user
    // parameterizes a login. Storing it would put a plaintext credential on
    // disk while the identical value typed into the Variables bar is
    // redirected to memory — so the value is dropped and re-entered there.
    const doc = {
      info: { name: "x" },
      item: [],
      variable: [
        { key: "site", value: "default" },
        { key: "password", value: "hunter2" },
        { key: "client_secret", value: "s3cr3t" },
      ],
    };
    const { collection: c, warnings } = importPostmanCollection(doc, seqIds());
    expect(c.variables).toHaveLength(3);
    expect(c.variables.find((v) => v.key === "site")?.value).toBe("default");
    expect(c.variables.find((v) => v.key === "password")?.value).toBe("");
    expect(c.variables.find((v) => v.key === "client_secret")?.value).toBe("");
    expect(JSON.stringify(c)).not.toContain("hunter2");
    expect(JSON.stringify(c)).not.toContain("s3cr3t");
    expect(warnings.some((w) => /never saved to disk/.test(w))).toBe(true);
    // `apiKey` is deliberately NOT credential-shaped: the API key is a
    // keychain-backed SecretRef on the session, never a collection variable,
    // so a variable of that name is just a non-secret label.
    const { collection: c2 } = importPostmanCollection(
      { info: { name: "y" }, item: [], variable: [{ key: "apiKey", value: "label" }] },
      seqIds(),
    );
    expect(c2.variables[0].value).toBe("label");
  });
});

describe("importPostmanCollection — bounds", () => {
  it("truncates a collection past the request cap with a warning", () => {
    const item = Array.from({ length: 2100 }, (_, i) => ({
      name: `r${i}`,
      request: { method: "GET", url: `/v1/x/${i}` },
    }));
    const { collection: c, warnings } = importPostmanCollection(
      { info: { name: "big" }, item },
      seqIds(),
    );
    expect(allRequests(c.root).length).toBeLessThanOrEqual(2000);
    expect(warnings.some((w) => /exceeded/.test(w))).toBe(true);
  });
});

describe("importPostmanCollection — rejection", () => {
  it("rejects a non-object", () => {
    expect(() => importPostmanCollection(null)).toThrow(/expected a JSON object/);
    expect(() => importPostmanCollection("nope")).toThrow(/expected a JSON object/);
  });

  it("gives a targeted message for a v1 collection", () => {
    expect(() => importPostmanCollection({ requests: [], order: [] })).toThrow(/v1 collection/);
  });

  it("rejects an object with no item array", () => {
    expect(() => importPostmanCollection({ info: { name: "x" } })).toThrow(
      /missing an .item. array/,
    );
  });

  it("imports an empty collection to an empty root", () => {
    const { collection: c } = importPostmanCollection(
      { info: { name: "empty" }, item: [] },
      seqIds(),
    );
    expect(c.root.requests).toHaveLength(0);
    expect(c.root.folders).toHaveLength(0);
  });
});

describe("collectGetEndpoints", () => {
  it("gathers GETs across folders, dedupes by path, drops writes (#12 Phase 2b)", () => {
    const coll: ApiCollection = {
      id: "c",
      name: "C",
      variables: [],
      root: {
        id: "r",
        name: "R",
        requests: [
          {
            id: "1",
            name: "List",
            method: "GET",
            path: "/people",
            headers: [],
            body: null,
            destructive: false,
          },
          {
            id: "2",
            name: "Create",
            method: "POST",
            path: "/people",
            headers: [],
            body: null,
            destructive: true,
          },
          {
            id: "3",
            name: "Dup",
            method: "GET",
            path: "/people",
            headers: [],
            body: null,
            destructive: false,
          },
        ],
        folders: [
          {
            id: "f",
            name: "F",
            folders: [],
            requests: [
              {
                id: "4",
                name: "Detail",
                method: "GET",
                path: "/people/{{id}}",
                headers: [],
                body: null,
                destructive: false,
              },
            ],
          },
        ],
      },
    };
    // POST dropped (agent is GET-only), duplicate /people collapsed, nested
    // folder walked, first-seen order preserved.
    expect(collectGetEndpoints([coll])).toEqual([
      ["List", "/people"],
      ["Detail", "/people/{{id}}"],
    ]);
  });
});

describe("scrubCredentialsFromBody (v4.3.0)", () => {
  // Imported + saved collections are persisted verbatim to localStorage. The
  // importer already stripped auth HEADERS, which made import *look*
  // credential-safe while a real password in a login BODY went to disk in
  // plaintext.

  it("rewrites a literal JSON credential to a {{variable}}", () => {
    const { body, scrubbed } = scrubCredentialsFromBody(
      '{"aaaUser":{"attributes":{"name":"admin","pwd":"hunter2"}}}',
    );
    expect(scrubbed).toEqual(["pwd"]);
    expect(body).toContain('"pwd": "{{pwd}}"');
    expect(body).not.toContain("hunter2");
    // the non-credential field is untouched
    expect(body).toContain('"name": "admin"');
  });

  it("rewrites a literal urlencoded credential", () => {
    const { body, scrubbed } = scrubCredentialsFromBody("j_username=admin&j_password=hunter2");
    expect(scrubbed).toEqual(["j_password"]);
    expect(body).toBe("j_username=admin&j_password={{j_password}}");
  });

  it("leaves an existing {{template}} alone (idempotent)", () => {
    const original = '{\n  "pwd": "{{password}}"\n}';
    const once = scrubCredentialsFromBody(original);
    expect(once.scrubbed).toEqual([]);
    expect(once.body).toBe(original);
    // and scrubbing twice is a no-op
    const first = scrubCredentialsFromBody('{"pwd":"hunter2"}');
    const second = scrubCredentialsFromBody(first.body);
    expect(second.scrubbed).toEqual([]);
    expect(second.body).toBe(first.body);
  });

  it("does not touch non-credential fields or unparseable bodies", () => {
    expect(scrubCredentialsFromBody('{"organizationId":"6699"}').scrubbed).toEqual([]);
    // `bypass` is not a credential (word-split, not substring)
    expect(scrubCredentialsFromBody('{"bypass":"yes"}').scrubbed).toEqual([]);
    // an unparseable blob is left ALONE rather than mangled
    const xml = "<login><password>hunter2</password></login>";
    expect(scrubCredentialsFromBody(xml)).toEqual({ body: xml, scrubbed: [] });
    expect(scrubCredentialsFromBody(null)).toEqual({ body: null, scrubbed: [] });
    expect(scrubCredentialsFromBody("")).toEqual({ body: "", scrubbed: [] });
  });

  it("preserves a __proto__ member instead of silently dropping it", () => {
    // A plain `{}` accumulator routes `out["__proto__"] = …` through
    // Object.prototype's setter, so the member never becomes an own property
    // and JSON.stringify omits it — corrupting the body we hand back.
    const { body, scrubbed } = scrubCredentialsFromBody(
      '{"__proto__":{"a":1},"password":"hunter2"}',
    );
    expect(scrubbed).toEqual(["password"]);
    expect(body).toContain("__proto__");
    expect(body).not.toContain("hunter2");
    // …and no actual prototype pollution happened.
    expect(({} as Record<string, unknown>).a).toBeUndefined();
  });

  it("catches all-lowercase compound credential names", () => {
    // `secretkey` is FortiGate's real /logincheck parameter, and both Fortis
    // are shipped vendors — the word-split alone missed it.
    const { scrubbed } = scrubCredentialsFromBody(
      '{"username":"admin","secretkey":"s3cr3t","authpassword":"x"}',
    );
    expect(scrubbed).toEqual(expect.arrayContaining(["secretkey", "authpassword"]));
  });

  it("reaches nested objects and arrays", () => {
    const { body, scrubbed } = scrubCredentialsFromBody(
      '{"params":[{"data":{"user":"admin","passwd":"s3cr3t"}}]}',
    );
    expect(scrubbed).toEqual(["passwd"]);
    expect(body).not.toContain("s3cr3t");
    expect(body).toContain("{{passwd}}");
  });

  it("an imported collection carrying a literal password does not persist it", () => {
    const src = {
      info: {
        name: "Vendor",
        schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
      },
      item: [
        {
          name: "Log in",
          request: {
            method: "POST",
            url: { raw: "https://x/api/aaaLogin.json", path: ["api", "aaaLogin.json"] },
            body: { mode: "raw", raw: '{"username":"admin","password":"hunter2"}' },
          },
        },
      ],
    };
    let n = 0;
    const res = importPostmanCollection(src, () => `id${n++}`);
    const serialized = JSON.stringify(res.collection);
    expect(serialized).not.toContain("hunter2");
    expect(serialized).toContain("{{password}}");
    expect(res.warnings.join(" ")).toMatch(/credentials are never saved to disk/);
  });
});
