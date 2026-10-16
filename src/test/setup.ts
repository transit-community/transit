import "@testing-library/jest-dom/vitest";

// happy-dom implements the modern CSSOM (`insertRule`/`deleteRule`) but not
// the legacy IE-era aliases. `react-resizable-panels` still calls
// `addRule`/`removeRule` when it sets the global resize cursor, so any test
// that mounts a PanelGroup with a resize handle throws on unmount. Shim only
// what is missing, so a future happy-dom that ships them wins.
const proto = globalThis.CSSStyleSheet?.prototype as
  | (CSSStyleSheet & {
      addRule?: (selector: string, style: string, index?: number) => number;
      removeRule?: (index?: number) => void;
    })
  | undefined;
if (proto) {
  proto.addRule ??= function (selector: string, style: string, index?: number) {
    return this.insertRule(`${selector} { ${style} }`, index ?? this.cssRules.length);
  };
  proto.removeRule ??= function (index?: number) {
    this.deleteRule(index ?? 0);
  };
}
