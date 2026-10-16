import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  probeSshKeys: vi.fn(),
  addAuthProfile: vi.fn(),
  enrollSecret: vi.fn(),
  // Pulled in transitively by the always-mounted AuthProfileDialog.
  updateAuthProfile: vi.fn(),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
}));

import { addAuthProfile, enrollSecret, probeSshKeys, type ImportIdentityMeta } from "@/lib/api";

import { CredentialMapStep } from "./CredentialMapStep";
import { initialImportState, type ImportState } from "./importReducer";

const mockedProbe = vi.mocked(probeSshKeys);
const mockedAdd = vi.mocked(addAuthProfile);
const mockedEnroll = vi.mocked(enrollSecret);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

function identity(
  over: Partial<ImportIdentityMeta> & { key: string; login: string },
): ImportIdentityMeta {
  return {
    count: 1,
    auth_kind: "public_key_file",
    suggested_backend: "ssh_key",
    key_path: null,
    ...over,
  };
}

const IDENTITIES: ImportIdentityMeta[] = [
  identity({ key: "u1", login: "sol", suggested_backend: "ssh_key", key_path: "/k/id_ed25519" }),
  identity({
    key: "u2",
    login: "ops",
    count: 2,
    suggested_backend: "ssh_key",
    key_path: "/k/id_rsa",
  }),
  identity({ key: "u3", login: "apt", suggested_backend: "ssh_agent", auth_kind: "agent" }),
  identity({ key: "u4", login: "root", suggested_backend: "keyring", auth_kind: "password" }),
];

function stateWith(identities: ImportIdentityMeta[]): ImportState {
  return { ...initialImportState, step: "credentials", identities };
}

beforeEach(() => {
  mockedAdd.mockResolvedValue(undefined);
  mockedEnroll.mockResolvedValue(undefined);
  mockedProbe.mockResolvedValue([
    { path: "/k/id_ed25519", verdict: { status: "unencrypted" } },
    { path: "/k/id_rsa", verdict: { status: "encrypted" } },
  ]);
});

afterEach(() => vi.clearAllMocks());

describe("CredentialMapStep — key probe + batch create", () => {
  it("shows the full key path with a title tooltip (not truncated)", async () => {
    renderWithQuery(
      <CredentialMapStep state={stateWith(IDENTITIES)} dispatch={vi.fn()} profiles={[]} />,
    );
    const pathLine = await screen.findByText(/SSH key — \/k\/id_ed25519/);
    expect(pathLine).toHaveAttribute("title", "/k/id_ed25519");
  });

  it("probes keys, badges them, and gates encrypted keys behind a passphrase", async () => {
    renderWithQuery(
      <CredentialMapStep state={stateWith(IDENTITIES)} dispatch={vi.fn()} profiles={[]} />,
    );

    // Probe drives the per-key verdict badges.
    expect(await screen.findByText("key ready")).toBeInTheDocument(); // u1 unencrypted
    expect(screen.getByText("encrypted")).toBeInTheDocument(); // u2 encrypted
    expect(screen.getByText("agent")).toBeInTheDocument(); // u3 ssh_agent

    // The probe was called once with the unique sorted key paths.
    expect(mockedProbe).toHaveBeenCalledWith(["/k/id_ed25519", "/k/id_rsa"]);

    // Eligible (no typed secret needed) = unencrypted key + agent = 2.
    // The encrypted key u2 is excluded until a passphrase is typed.
    expect(
      await screen.findByRole("button", { name: /create 2 key profiles/i }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("cred-passphrase-u2")).toBeInTheDocument();
    // The password identity (u4) gets no passphrase field and no badge.
    expect(screen.queryByTestId("cred-passphrase-u4")).not.toBeInTheDocument();
  });

  it("batch-creates agent + unencrypted-key + encrypted-key profiles correctly", async () => {
    const dispatch = vi.fn();
    renderWithQuery(
      <CredentialMapStep state={stateWith(IDENTITIES)} dispatch={dispatch} profiles={[]} />,
    );

    // Type the encrypted key's passphrase → it becomes batch-eligible.
    const pass = await screen.findByTestId("cred-passphrase-u2");
    await userEvent.type(pass, "hunter2");
    const button = await screen.findByRole("button", { name: /create 3 key profiles/i });
    await userEvent.click(button);

    await waitFor(() => expect(mockedAdd).toHaveBeenCalledTimes(3));

    // Unencrypted key → no passphrase ref.
    expect(mockedAdd).toHaveBeenCalledWith("sol", {
      username: "sol",
      secret: { backend: "ssh_key", path: "/k/id_ed25519", passphrase: null },
    });
    // Agent → fingerprint-less ssh_agent ref, no secret.
    expect(mockedAdd).toHaveBeenCalledWith("apt", {
      username: "apt",
      secret: { backend: "ssh_agent", public_key_fingerprint: null },
    });
    // Encrypted key → nested keyring ref keyed off the profile name.
    expect(mockedAdd).toHaveBeenCalledWith("ops", {
      username: "ops",
      secret: {
        backend: "ssh_key",
        path: "/k/id_rsa",
        passphrase: { backend: "keyring", key: "transit/ops-passphrase" },
      },
    });

    // The passphrase is enrolled to the keychain — only for the encrypted
    // key, and never for the unencrypted key or the agent.
    expect(mockedEnroll).toHaveBeenCalledTimes(1);
    expect(mockedEnroll).toHaveBeenCalledWith("ops", "hunter2");

    // Each created profile is mapped back to its identity.
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_CREDENTIAL",
      identityKey: "u1",
      profileName: "sol",
    });
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_CREDENTIAL",
      identityKey: "u2",
      profileName: "ops",
    });
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_CREDENTIAL",
      identityKey: "u3",
      profileName: "apt",
    });
  });

  it("flags an unparseable key and excludes it from the batch", async () => {
    mockedProbe.mockResolvedValue([
      { path: "/k/id_ed25519", verdict: { status: "unparseable", hint: "convert with puttygen" } },
    ]);
    const onlyBadKey = [IDENTITIES[0]];
    renderWithQuery(
      <CredentialMapStep state={stateWith(onlyBadKey)} dispatch={vi.fn()} profiles={[]} />,
    );

    expect(await screen.findByText(/can.t read key/i)).toBeInTheDocument();
    // Nothing batchable → no batch banner/button.
    expect(
      screen.queryByRole("button", { name: /create .* key profile/i }),
    ).not.toBeInTheDocument();
  });
});
