import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  addAuthProfile: vi.fn(),
  updateAuthProfile: vi.fn(),
  enrollSecret: vi.fn(),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
}));

import { AuthProfileDialog } from "./AuthProfileDialog";

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

afterEach(() => vi.clearAllMocks());

describe("AuthProfileDialog add-mode prefill (import suggestion)", () => {
  it("seeds backend, key path, and username from an ssh_key suggestion", async () => {
    renderWithQuery(
      <AuthProfileDialog
        open
        mode="add"
        suggestion={{
          backend: "ssh_key",
          ssh_key_path: "/Users/k/.ssh/id_ed25519",
          username: "sol",
        }}
        onOpenChange={vi.fn()}
      />,
    );

    // The ssh_key section is shown (backend resolved to ssh_key), and the
    // path the importer found is prefilled — no re-typing.
    const pathField = (await screen.findByLabelText(/private key file/i)) as HTMLInputElement;
    await waitFor(() => expect(pathField.value).toBe("/Users/k/.ssh/id_ed25519"));

    const usernameField = screen.getByLabelText(/username/i) as HTMLInputElement;
    expect(usernameField.value).toBe("sol");
  });

  it("falls back to the keyring default when no suggestion is given", async () => {
    renderWithQuery(<AuthProfileDialog open mode="add" onOpenChange={vi.fn()} />);

    // Keyring is the default backend → its OS-keyring field renders and
    // there is no ssh_key path field.
    expect(await screen.findByLabelText(/os keyring friendly name/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/private key file/i)).not.toBeInTheDocument();
  });
});

describe("AuthProfileDialog edit-mode prefill (ssh_key key_path)", () => {
  it("prefills the key path from existingMeta so Edit doesn't force a re-Browse", async () => {
    renderWithQuery(
      <AuthProfileDialog
        open
        mode="edit"
        existingName="lab-key"
        existingMeta={{ username: "alice", backend: "ssh_key", key_path: "/Users/k/.ssh/id_lab" }}
        onOpenChange={vi.fn()}
      />,
    );

    // The path is a non-secret filesystem reference (Rule 1), so edit
    // mode shows the stored value instead of an empty field.
    const pathField = (await screen.findByLabelText(/private key file/i)) as HTMLInputElement;
    await waitFor(() => expect(pathField.value).toBe("/Users/k/.ssh/id_lab"));
    expect((screen.getByLabelText(/username/i) as HTMLInputElement).value).toBe("alice");
  });

  it("leaves the path empty when the stored profile has none", async () => {
    renderWithQuery(
      <AuthProfileDialog
        open
        mode="edit"
        existingName="lab-pw"
        existingMeta={{ username: "alice", backend: "ssh_key", key_path: null }}
        onOpenChange={vi.fn()}
      />,
    );

    const pathField = (await screen.findByLabelText(/private key file/i)) as HTMLInputElement;
    await waitFor(() => expect(pathField.value).toBe(""));
  });
});
