/**
 * Resolve a raw imported jump-host value (ssh_config `ProxyJump` /
 * SecureCRT `Firewall Name`) to a device id — v6.5.0, extracted pure
 * after adversarial review found the inline version guessing.
 *
 * Contract: **never guess.**
 * - Pass 1: exact id/alias match (ssh_config semantics — an alias
 *   outranks a coincidental host match).
 * - Pass 2: host match only when it is UNIQUE across the candidate
 *   pool; two devices sharing a host (same box, two ports) is
 *   ambiguity, and ambiguity drops.
 * - A `:port` qualifier must AGREE with the matched device's port,
 *   or the value drops (binding `bastion:2222` to the port-22 device
 *   would silently discard the user's intent).
 * - IPv6-safe: `[::1]:2222` unbrackets + port-checks; a bare IPv6
 *   host (`fe80::1`, 2+ colons, no brackets) is never port-stripped.
 *
 * Returns the matched device id, or `null` = drop (the caller counts
 * drops for the toast; the caller also owns the self-reference drop,
 * since only it knows which row is resolving).
 */

export interface JumpCandidate {
  id: string;
  host: string;
  port: number;
}

/** Split `user@host`, `host:port`, `[v6]:port`, `[v6]` into parts. */
function parseTarget(raw: string): { host: string; port: number | null } {
  const noUser = raw.replace(/^[^@]*@/, "");
  const bracketed = noUser.match(/^\[(.+)\]:(\d+)$/);
  if (bracketed) return { host: bracketed[1], port: Number(bracketed[2]) };
  const bare = noUser.match(/^\[(.+)\]$/);
  if (bare) return { host: bare[1], port: null };
  // `host:port` only when exactly one colon — a second colon means a
  // bare IPv6 address, which must not be mangled.
  const single = noUser.match(/^([^:]+):(\d+)$/);
  if (single) return { host: single[1], port: Number(single[2]) };
  return { host: noUser, port: null };
}

/**
 * Post-resolution sweep (adversarial-review finding): resolved refs can
 * still form graphs the backend refuses ATOMICALLY — a mutual ProxyJump
 * pair inside one batch is a cycle, and a batch chain stacked on an
 * existing chain can exceed the depth cap; either would abort the whole
 * import with a raw loader error. Returns the row IDS whose ref must be
 * dropped (walked against the ORIGINAL graph, so the verdict is
 * order-independent and never guesses which side of a cycle to keep —
 * both drop, and the toast counts them).
 */
export function pruneJumpRefs(
  rowJumps: Map<string, string>,
  existingJumpOf: Map<string, string>,
  maxDepth: number = 4,
): Set<string> {
  const next = (id: string): string | undefined => rowJumps.get(id) ?? existingJumpOf.get(id);
  const drop = new Set<string>();
  for (const [rowId] of rowJumps) {
    const visited = new Set<string>([rowId]);
    let hops = 0;
    let cursor = next(rowId);
    let bad = false;
    while (cursor !== undefined) {
      hops += 1;
      if (hops > maxDepth || visited.has(cursor)) {
        bad = true;
        break;
      }
      visited.add(cursor);
      cursor = next(cursor);
    }
    if (bad) drop.add(rowId);
  }
  return drop;
}

export function resolveJumpHost(raw: string, candidates: JumpCandidate[]): string | null {
  const t = raw.trim();
  if (t === "") return null;
  const { host, port } = parseTarget(t);

  const portAgrees = (c: JumpCandidate) => port === null || c.port === port;

  // Pass 1 — exact id/alias. Ids are unique within a pool half, but the
  // pool concatenates in-batch rows with existing inventory; a same-id
  // pair would collide at import commit anyway, so first match is safe.
  const byId = candidates.find((c) => c.id === t || c.id === host);
  if (byId) return portAgrees(byId) ? byId.id : null;

  // Pass 2 — unique host only.
  const byHost = candidates.filter((c) => c.host === host);
  if (byHost.length === 1) return portAgrees(byHost[0]) ? byHost[0].id : null;
  return null;
}
