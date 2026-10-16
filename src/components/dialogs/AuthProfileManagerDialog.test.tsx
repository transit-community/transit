import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  listAuthProfiles: vi.fn(),
  addAuthProfile: vi.fn(),
  updateAuthProfile: vi.fn(),
  deleteAuthProfile: vi.fn(),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
  testSecretResolve: vi.fn(),
  enrollSecret: vi.fn(),
}));

import {
  type AuthProfileMeta,
  type DeviceMeta,
  deleteAuthProfile,
  listAuthProfiles,
  listDevices,
  testSecretResolve,
} from "@/lib/api";

import { AuthProfileManagerDialog } from "./AuthProfileManagerDialog";

const mockedListAuthProfiles = vi.mocked(listAuthProfiles);
const mockedListDevices = vi.mocked(listDevices);
const mockedDeleteAuthProfile = vi.mocked(deleteAuthProfile);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

const SAMPLE_PROFILES: AuthProfileMeta[] = [
  { name: "lab-pw", username: "alice", backend: "keyring", key_path: null },
  { name: "labssh-ios", username: "alice", backend: "ssh_agent", key_path: null },
  { name: "unused-profile", username: "ops", backend: "op", key_path: null },
];

function device(id: string, auth: string): DeviceMeta {
  return {
    id,
    host: "1.2.3.4",
    port: 22,
    vendor: "junos",
    group: null,
    auth,
    syntax_highlighting: null,
    quick_copy_paste: null,
    font_family: null,
    font_size: null,
    bold_color: null,
    color: null,
    tags: [],
    allow_weak_crypto: null,
    netbox_id: null,
    jump_via: null,
    forward_agent: null,
  };
}

beforeEach(() => {
  mockedListAuthProfiles.mockResolvedValue(SAMPLE_PROFILES);
  mockedListDevices.mockResolvedValue([
    device("vEX1", "lab-pw"),
    device("vEX2", "lab-pw"),
    device("CSR1", "labssh-ios"),
  ]);
  mockedDeleteAuthProfile.mockResolvedValue();
  // Default: every keyring profile reports enrolled
  // (test_secret_resolve returns a length). Per-test overrides
  // switch to rejection to exercise the "Secret not enrolled"
  // badge path.
  vi.mocked(testSecretResolve).mockResolvedValue({ length: 16 });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("AuthProfileManagerDialog", () => {
  it("renders nothing when closed", () => {
    renderWithQuery(<AuthProfileManagerDialog open={false} onOpenChange={vi.fn()} />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renders the empty state when no profiles exist", async () => {
    mockedListAuthProfiles.mockResolvedValue([]);
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    expect(await screen.findByText(/no auth profiles yet/i)).toBeInTheDocument();
    // The "Add" button at the top of the dialog opens AuthProfileDialog
    // in add mode. Use the testid to disambiguate from the empty-state
    // CTA also labeled "New profile".
    await userEvent.click(screen.getByTestId("auth-profile-add"));
    await waitFor(() => {
      expect(screen.getByText(/^new auth profile$/i)).toBeInTheDocument();
    });
  });

  it("lists profiles with backend badges + usage counts", async () => {
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    const list = await screen.findByTestId("auth-profile-list");
    expect(within(list).getByText("lab-pw")).toBeInTheDocument();
    expect(within(list).getByText("labssh-ios")).toBeInTheDocument();
    expect(within(list).getByText("unused-profile")).toBeInTheDocument();

    // Backend badges
    expect(within(list).getByText("keyring")).toBeInTheDocument();
    expect(within(list).getByText("ssh_agent")).toBeInTheDocument();
    expect(within(list).getByText("op")).toBeInTheDocument();

    // Usage counts
    expect(screen.getByTestId("auth-profile-usage-lab-pw")).toHaveTextContent("Used by 2");
    expect(screen.getByTestId("auth-profile-usage-labssh-ios")).toHaveTextContent("Used by 1");
    // Unused profile shows "Unused" not a button
    expect(screen.queryByTestId("auth-profile-usage-unused-profile")).not.toBeInTheDocument();
  });

  it("expanding the usage badge reveals the dependent device list", async () => {
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    await screen.findByTestId("auth-profile-list");
    await userEvent.click(screen.getByTestId("auth-profile-usage-lab-pw"));

    const usageList = await screen.findByTestId("auth-profile-usage-list-lab-pw");
    expect(within(usageList).getByText("vEX1")).toBeInTheDocument();
    expect(within(usageList).getByText("vEX2")).toBeInTheDocument();
  });

  it("delete blocks when the profile is referenced by devices", async () => {
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    await screen.findByTestId("auth-profile-list");
    await userEvent.click(screen.getByTestId("auth-profile-delete-lab-pw"));

    const alert = await screen.findByTestId("auth-profile-delete-alert");
    expect(within(alert).getByText(/can't delete lab-pw/i)).toBeInTheDocument();
    expect(within(alert).getByText("vEX1")).toBeInTheDocument();
    expect(within(alert).getByText("vEX2")).toBeInTheDocument();
    // Confirm button is NOT shown when in use
    expect(screen.queryByTestId("auth-profile-delete-confirm")).not.toBeInTheDocument();
    // Backend mutation never called
    expect(mockedDeleteAuthProfile).not.toHaveBeenCalled();
  });

  it("delete succeeds when the profile is unused", async () => {
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    await screen.findByTestId("auth-profile-list");
    await userEvent.click(screen.getByTestId("auth-profile-delete-unused-profile"));

    const confirm = await screen.findByTestId("auth-profile-delete-confirm");
    await userEvent.click(confirm);

    await waitFor(() => {
      expect(mockedDeleteAuthProfile).toHaveBeenCalledWith("unused-profile");
    });
  });

  it("edit opens AuthProfileDialog in edit mode with prefilled fields", async () => {
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    await screen.findByTestId("auth-profile-list");
    await userEvent.click(screen.getByTestId("auth-profile-edit-lab-pw"));

    // AuthProfileDialog appears with title "Edit auth profile"
    await screen.findByText(/^edit auth profile$/i);

    // Username field is prefilled (verified via the form input's value)
    const usernameField = screen.getByLabelText(/username/i) as HTMLInputElement;
    expect(usernameField.value).toBe("alice");
  });

  it("Add button opens AuthProfileDialog in add mode", async () => {
    renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);

    await screen.findByTestId("auth-profile-list");
    await userEvent.click(screen.getByTestId("auth-profile-add"));

    await screen.findByText(/^new auth profile$/i);
  });

  describe("Secret-not-enrolled badge (Phase 7a C14)", () => {
    it("renders no badge when test_secret_resolve succeeds", async () => {
      vi.mocked(testSecretResolve).mockResolvedValue({ length: 12 });
      renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);
      await screen.findByTestId("auth-profile-list");
      await waitFor(() =>
        expect(screen.queryByTestId("auth-profile-not-enrolled-lab-pw")).not.toBeInTheDocument(),
      );
    });

    it("renders the badge when test_secret_resolve rejects for a keyring profile", async () => {
      vi.mocked(testSecretResolve).mockRejectedValue(new Error("NotFound"));
      renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);
      await screen.findByTestId("auth-profile-list");
      expect(await screen.findByTestId("auth-profile-not-enrolled-lab-pw")).toBeInTheDocument();
    });

    it("clicking the badge opens the AuthProfileDialog in edit mode", async () => {
      vi.mocked(testSecretResolve).mockRejectedValue(new Error("NotFound"));
      renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);
      await screen.findByTestId("auth-profile-list");

      const badge = await screen.findByTestId("auth-profile-not-enrolled-lab-pw");
      await userEvent.click(badge);
      await screen.findByText(/^edit auth profile$/i);
      // The secret-value input should be present (keyring backend).
      expect(await screen.findByTestId("auth-profile-secret-value")).toBeInTheDocument();
    });

    it("does NOT probe non-keyring backends", async () => {
      // Reset and assert that listAuthProfiles came back but
      // testSecretResolve was only invoked for keyring rows.
      vi.mocked(testSecretResolve).mockResolvedValue({ length: 4 });
      renderWithQuery(<AuthProfileManagerDialog open onOpenChange={vi.fn()} />);
      await screen.findByTestId("auth-profile-list");
      await waitFor(() =>
        expect(vi.mocked(testSecretResolve).mock.calls.map((c) => c[0])).toEqual(["lab-pw"]),
      );
    });
  });
});
