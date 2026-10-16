import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SaveRequestPopover, type SaveableRequest } from "@/components/SaveRequestPopover";
import { useApiCollectionsStore } from "@/stores/apiCollectionsStore";

// Radix Popover uses ResizeObserver; happy-dom lacks it.
class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}
(globalThis as unknown as { ResizeObserver: typeof StubResizeObserver }).ResizeObserver =
  StubResizeObserver;

vi.mock("@/lib/toast", () => ({
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toastInfo: vi.fn(),
}));

function reset() {
  localStorage.clear();
  useApiCollectionsStore.setState({ byController: {} });
}

const openTrigger = { name: "Save request to a collection" };
const saveButton = { name: "Save request" };

function renderPane(request: SaveableRequest) {
  return render(<SaveRequestPopover apiSessionId="c1" request={request} />);
}

describe("SaveRequestPopover", () => {
  beforeEach(reset);
  afterEach(() => vi.clearAllMocks());

  it("disables the trigger when there is nothing to save", () => {
    renderPane({ method: "GET", path: "   ", headers: [], body: null });
    expect(screen.getByRole("button", openTrigger)).toBeDisabled();
  });

  it("saves the current request into a brand-new collection", async () => {
    renderPane({ method: "GET", path: "/v1/hosts", headers: [], body: null });
    await userEvent.click(screen.getByRole("button", openTrigger));

    // Name defaults to the path; no collections exist → "New collection" mode.
    expect(await screen.findByLabelText("Request name")).toHaveValue("/v1/hosts");
    await userEvent.type(screen.getByLabelText("New collection name"), "My reads");
    await userEvent.click(screen.getByRole("button", saveButton));

    const cols = useApiCollectionsStore.getState().collectionsFor("c1");
    expect(cols).toHaveLength(1);
    expect(cols[0].name).toBe("My reads");
    expect(cols[0].root.requests[0].path).toBe("/v1/hosts");
    expect(cols[0].root.requests[0].destructive).toBe(false);
  });

  it("saves into the auto-selected existing collection, flags writes, and strips auth headers", async () => {
    useApiCollectionsStore.getState().createCollection("c1", "Existing");
    renderPane({
      method: "POST",
      path: "/v1/x",
      // An auth header the user typed must NEVER be persisted (key is injected
      // server-side); the plain header survives.
      headers: [
        { key: "A", value: "b" },
        { key: "X-API-KEY", value: "super-secret" },
        { key: "Authorization", value: "Bearer nope" },
      ],
      body: "{}",
    });
    await userEvent.click(screen.getByRole("button", openTrigger));
    // Existing collection auto-selected — just save.
    await userEvent.click(screen.getByRole("button", saveButton));

    const col = useApiCollectionsStore.getState().collectionsFor("c1")[0];
    expect(col.name).toBe("Existing");
    expect(col.root.requests).toHaveLength(1);
    expect(col.root.requests[0].method).toBe("POST");
    expect(col.root.requests[0].destructive).toBe(true);
    expect(col.root.requests[0].headers).toEqual([{ key: "A", value: "b" }]);
  });

  it("keeps Save disabled until a new-collection name is given", async () => {
    renderPane({ method: "GET", path: "/v1/hosts", headers: [], body: null });
    await userEvent.click(screen.getByRole("button", openTrigger));
    // New-collection mode with an empty name → Save disabled.
    expect(screen.getByRole("button", saveButton)).toBeDisabled();
    await userEvent.type(screen.getByLabelText("New collection name"), "Named");
    expect(screen.getByRole("button", saveButton)).toBeEnabled();
  });
});
