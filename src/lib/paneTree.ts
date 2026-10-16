/**
 * v4.4.0 Commit B — pane layout tree for terminal tab tiling.
 *
 * A tab's content is a `PaneNode`: either a single terminal (`leaf`,
 * referencing a backend session id) or a `split` (`row` = side-by-side,
 * `col` = stacked) of two-or-more child nodes. Arbitrary grids fall out of
 * nesting splits, exactly like Windows Terminal / wezterm / tmux.
 *
 * Pane SIZES are intentionally NOT stored here — `react-resizable-panels`
 * owns them in its own (mounted) state, so they persist across tab switches
 * (panes stay force-mounted) and reset on a structural change, matching the
 * old 2-up splitter's behavior. These functions are PURE + immutable so the
 * store and tests can reason about layout without touching React.
 */
export type PaneNode =
  { type: "leaf"; sessionId: string } | { type: "split"; dir: "row" | "col"; children: PaneNode[] };

export function leaf(sessionId: string): PaneNode {
  return { type: "leaf", sessionId };
}

/** Every leaf session id, in render order (left→right / top→bottom). */
export function paneIds(node: PaneNode): string[] {
  return node.type === "leaf" ? [node.sessionId] : node.children.flatMap(paneIds);
}

/** Number of panes (leaves) in the tree. */
export function paneCount(node: PaneNode): number {
  return node.type === "leaf" ? 1 : node.children.reduce((n, c) => n + paneCount(c), 0);
}

/** Whether `sessionId` is a leaf anywhere in the tree. */
export function hasPane(node: PaneNode, sessionId: string): boolean {
  return node.type === "leaf"
    ? node.sessionId === sessionId
    : node.children.some((c) => hasPane(c, sessionId));
}

/**
 * Split the leaf `targetId` in two along `dir`, inserting `newId` immediately
 * after it. If the target's parent already splits along `dir`, the new pane is
 * appended as a SIBLING (a flat N-way split) rather than nesting a 2-way inside
 * it — so "split right" three times gives three columns, not deeply nested
 * pairs (matches wezterm / tmux). Returns a NEW tree; unchanged if `targetId`
 * isn't a leaf anywhere in the tree.
 */
export function splitLeaf(
  node: PaneNode,
  targetId: string,
  newId: string,
  dir: "row" | "col",
): PaneNode {
  if (node.type === "leaf") {
    if (node.sessionId !== targetId) return node;
    return { type: "split", dir, children: [leaf(targetId), leaf(newId)] };
  }
  // Same-direction parent + a direct-child target leaf → flat sibling insert.
  if (node.dir === dir) {
    const idx = node.children.findIndex((c) => c.type === "leaf" && c.sessionId === targetId);
    if (idx !== -1) {
      const children = [...node.children];
      children.splice(idx + 1, 0, leaf(newId));
      return { ...node, children };
    }
  }
  // Otherwise recurse — the target may be a leaf under a differently-oriented
  // split, which becomes a nested 2-way there.
  return { ...node, children: node.children.map((c) => splitLeaf(c, targetId, newId, dir)) };
}

/**
 * Insert an arbitrary subtree `newNode` adjacent to the leaf `targetId`, along
 * `dir`, on the `before` side (true = left/top, false = right/bottom). Unlike
 * `splitLeaf` (which inserts a single NEW leaf after a target), this moves a
 * whole existing node — used by drag-to-split, where the dragged tab may itself
 * be a multi-pane subtree. Returns a NEW tree; unchanged if `targetId` isn't a
 * leaf anywhere. Same flat-vs-nested rule as `splitLeaf`: a same-`dir` parent
 * gets a flat sibling insert; otherwise the target leaf nests.
 */
export function insertNodeAt(
  node: PaneNode,
  targetId: string,
  newNode: PaneNode,
  dir: "row" | "col",
  before: boolean,
): PaneNode {
  if (node.type === "leaf") {
    if (node.sessionId !== targetId) return node;
    const children = before ? [newNode, leaf(targetId)] : [leaf(targetId), newNode];
    return { type: "split", dir, children };
  }
  if (node.dir === dir) {
    const idx = node.children.findIndex((c) => c.type === "leaf" && c.sessionId === targetId);
    if (idx !== -1) {
      const children = [...node.children];
      children.splice(before ? idx : idx + 1, 0, newNode);
      return { ...node, children };
    }
  }
  return {
    ...node,
    children: node.children.map((c) => insertNodeAt(c, targetId, newNode, dir, before)),
  };
}

/**
 * Remove the leaf `sessionId`. An empty split collapses away (returns `null`),
 * but a split left with a SINGLE child is deliberately KEPT (not collapsed to
 * that child). Collapsing would change the element type React renders at that
 * position (`<PanelGroup>` → `<TerminalPane>`), which unmounts + remounts the
 * surviving pane's xterm and loses its scrollback — see `PaneTree`. Keeping a
 * degenerate single-child split renders identically (one panel, no divider)
 * and keeps every untouched pane mounted. Returns the new tree, or `null` when
 * the ENTIRE tab was just that one pane (the caller removes the tab).
 */
export function removeLeaf(node: PaneNode, sessionId: string): PaneNode | null {
  if (node.type === "leaf") {
    return node.sessionId === sessionId ? null : node;
  }
  const children = node.children
    .map((c) => removeLeaf(c, sessionId))
    .filter((c): c is PaneNode => c !== null);
  if (children.length === 0) return null;
  return { ...node, children };
}

/**
 * Rename a leaf's session id everywhere in the tree (`oldId` → `newId`).
 * Used when a session id changes under the same tab — e.g. an SSH pane
 * reconnecting in place swaps its backend session id but keeps its slot.
 */
export function renameLeaf(node: PaneNode, oldId: string, newId: string): PaneNode {
  if (node.type === "leaf") {
    return node.sessionId === oldId ? leaf(newId) : node;
  }
  return { ...node, children: node.children.map((c) => renameLeaf(c, oldId, newId)) };
}

/**
 * The pane to focus after `removedId` is closed: its previous sibling leaf if
 * any, else the first remaining leaf, else `null` (tab is gone). Keeps focus
 * sensible when a pane closes.
 */
export function neighborPane(node: PaneNode, removedId: string): string | null {
  const before = paneIds(node);
  const idx = before.indexOf(removedId);
  const after = removeLeaf(node, removedId);
  if (after === null) return null;
  const remaining = paneIds(after);
  if (idx > 0 && remaining.includes(before[idx - 1])) return before[idx - 1];
  return remaining[0] ?? null;
}
