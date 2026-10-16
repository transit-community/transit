import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

import { MapButtonDialog } from "@/components/dialogs/MapButtonDialog";
import { useUiStore } from "@/stores/uiStore";

// Radix Dialog/Select touch ResizeObserver; happy-dom lacks it.
class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}
(globalThis as unknown as { ResizeObserver: typeof StubResizeObserver }).ResizeObserver =
  StubResizeObserver;

/** Reset to a single empty active bar so each test starts clean. */
function reset() {
  localStorage.clear();
  useUiStore.setState({
    preferences: {
      ...useUiStore.getState().preferences,
      buttonBars: [{ id: "test-bar", name: "Default", buttons: [] }],
      activeButtonBarId: "test-bar",
    },
  });
}

function activeButtons() {
  const p = useUiStore.getState().preferences;
  return p.buttonBars.find((b) => b.id === p.activeButtonBarId)!.buttons;
}

describe("MapButtonDialog color (Jeff Kish per-button shade)", () => {
  beforeEach(reset);

  it("saves a new button with the chosen palette color", async () => {
    render(<MapButtonDialog state={{ kind: "new" }} onClose={() => {}} />);

    await userEvent.type(screen.getByLabelText("Label"), "voip-test");
    await userEvent.type(screen.getByLabelText("String"), "mute");
    await userEvent.click(screen.getByRole("radio", { name: "Blue" }));
    await userEvent.click(screen.getByTestId("map-button-save"));

    const added = activeButtons().find((b) => b.label === "voip-test");
    expect(added?.color).toBe("blue");
  });

  it("clears the shade when editing a colored button and picking None", async () => {
    const existing = { id: "btn-1", label: "voip", value: "x", color: "blue" };
    useUiStore.setState({
      preferences: {
        ...useUiStore.getState().preferences,
        buttonBars: [{ id: "test-bar", name: "Default", buttons: [existing] }],
        activeButtonBarId: "test-bar",
      },
    });
    render(<MapButtonDialog state={{ kind: "edit", button: existing }} onClose={() => {}} />);

    // The picker reflects the current color, then we choose None.
    expect(screen.getByRole("radio", { name: "Blue" })).toHaveAttribute("aria-checked", "true");
    await userEvent.click(screen.getByRole("radio", { name: "No color" }));
    await userEvent.click(screen.getByTestId("map-button-save"));

    expect(activeButtons().find((b) => b.id === "btn-1")?.color).toBeUndefined();
  });
});
