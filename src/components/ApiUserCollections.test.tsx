import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiUserCollections } from "@/components/ApiUserCollections";
import { useApiCollectionsStore } from "@/stores/apiCollectionsStore";

vi.mock("@/lib/toast", () => ({
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
  toastInfo: vi.fn(),
}));

function reset() {
  localStorage.clear();
  useApiCollectionsStore.setState({ byController: {} });
}

const POSTMAN_DOC = {
  info: {
    name: "UniFi reads",
    schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
  },
  item: [
    {
      name: "List hosts",
      request: {
        method: "GET",
        url: { raw: "https://api.ui.com/v1/hosts", path: ["v1", "hosts"] },
        header: [],
      },
    },
  ],
};

function jsonFile(obj: unknown, name = "c.json") {
  return new File([JSON.stringify(obj)], name, { type: "application/json" });
}

describe("ApiUserCollections", () => {
  beforeEach(reset);
  afterEach(() => vi.clearAllMocks());

  it("creates a collection via the inline New input", async () => {
    render(<ApiUserCollections apiSessionId="c1" depth={0} onPick={() => {}} />);
    await userEvent.click(screen.getByText("New collection"));
    await userEvent.type(screen.getByLabelText("New collection name"), "My reads{Enter}");

    expect(useApiCollectionsStore.getState().collectionsFor("c1")[0].name).toBe("My reads");
    expect(screen.getByText("My reads")).toBeInTheDocument();
  });

  it("imports a Postman v2.1 collection from a file and toasts success", async () => {
    const { toastSuccess } = await import("@/lib/toast");
    render(<ApiUserCollections apiSessionId="c1" depth={0} onPick={() => {}} />);

    fireEvent.change(screen.getByTestId("postman-import-input"), {
      target: { files: [jsonFile(POSTMAN_DOC)] },
    });

    await waitFor(() =>
      expect(useApiCollectionsStore.getState().collectionsFor("c1")).toHaveLength(1),
    );
    expect(useApiCollectionsStore.getState().collectionsFor("c1")[0].name).toBe("UniFi reads");
    expect(toastSuccess).toHaveBeenCalled();
  });

  it("toasts an error and imports nothing for a non-Postman file", async () => {
    const { toastError } = await import("@/lib/toast");
    render(<ApiUserCollections apiSessionId="c1" depth={0} onPick={() => {}} />);

    fireEvent.change(screen.getByTestId("postman-import-input"), {
      target: { files: [jsonFile({ not: "a collection" })] },
    });

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(useApiCollectionsStore.getState().collectionsFor("c1")).toEqual([]);
  });

  it("deletes a collection only after the two-click confirm", async () => {
    useApiCollectionsStore.getState().createCollection("c1", "Doomed");
    render(<ApiUserCollections apiSessionId="c1" depth={0} onPick={() => {}} />);
    expect(screen.getByText("Doomed")).toBeInTheDocument();

    // First click arms the confirm — nothing deleted yet.
    await userEvent.click(screen.getByLabelText("Delete collection Doomed"));
    expect(useApiCollectionsStore.getState().collectionsFor("c1")).toHaveLength(1);

    // Confirm actually removes it.
    await userEvent.click(screen.getByLabelText("Confirm delete Doomed"));
    expect(useApiCollectionsStore.getState().collectionsFor("c1")).toEqual([]);
  });

  it("loads a saved request into the pane via onPick", async () => {
    const colId = useApiCollectionsStore.getState().createCollection("c1", "Reads");
    useApiCollectionsStore.getState().saveRequest("c1", colId, {
      name: "List hosts",
      method: "GET",
      path: "/v1/hosts",
      headers: [],
      body: null,
      destructive: false,
    });
    const onPick = vi.fn();
    render(<ApiUserCollections apiSessionId="c1" depth={0} onPick={onPick} />);

    await userEvent.click(screen.getByText("List hosts"));
    expect(onPick).toHaveBeenCalledWith(expect.objectContaining({ path: "/v1/hosts" }));
  });
});
