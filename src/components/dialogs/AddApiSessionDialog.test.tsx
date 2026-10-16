import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", async (importOriginal) => {
  // Keep the real type-only exports; stub every IPC wrapper the dialog's
  // mutation hooks reach.
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    addApiSession: vi.fn().mockResolvedValue(undefined),
    updateApiSession: vi.fn().mockResolvedValue(undefined),
    enrollApiSessionSecret: vi.fn().mockResolvedValue(undefined),
  };
});

import { addApiSession, enrollApiSessionSecret, type ApiSessionInput } from "@/lib/api";

import { AddApiSessionDialog } from "./AddApiSessionDialog";

const mockedAdd = vi.mocked(addApiSession);
const mockedEnroll = vi.mocked(enrollApiSessionSecret);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  vi.clearAllMocks();
});

// The dialog's Field labels are unassociated (no htmlFor), so queries go by
// the user-visible placeholder / display value instead — same information a
// sighted user navigates by.
const idInput = () => screen.getByPlaceholderText("office-unifi");
const nameInput = () => screen.getByPlaceholderText("Office UniFi");
const baseUrlInput = () => screen.getByPlaceholderText("https://swapi.dev/api");
const headerInput = () => screen.getByPlaceholderText("X-API-KEY");
// testing-library normalizes attribute whitespace, so the "Token " placeholder
// (trailing space) matches the trimmed string. Value assertions stay exact.
const prefixInput = () => screen.getByPlaceholderText("Token");
const keyInput = () => screen.getByPlaceholderText(/paste the credential/i);

describe("AddApiSessionDialog — NetBox preset (v6.2.0)", () => {
  it("picking NetBox presets api_key + Authorization + 'Token ' and submits the prefix untrimmed", async () => {
    const onOpenChange = vi.fn();
    renderWithQuery(<AddApiSessionDialog open onOpenChange={onOpenChange} />);

    await userEvent.type(idInput(), "netbox-lab");
    await userEvent.type(nameInput(), "NetBox (lab)");
    // The vendor select initially shows UniFi — the one select displaying it.
    await userEvent.selectOptions(screen.getByDisplayValue("UniFi (Ubiquiti)"), "netbox");

    // NetBox is a base-URL vendor: the kind selector disappears, Base URL shows.
    await userEvent.type(baseUrlInput(), "https://netbox.lab/api");

    // The preset landed in the Auth tab: scheme api_key, header Authorization,
    // value prefix "Token " — visible for editing, not hidden magic.
    await userEvent.click(screen.getByRole("tab", { name: /authentication/i }));
    expect(screen.getByDisplayValue("API key (custom header)")).toBeInTheDocument();
    expect(headerInput()).toHaveValue("Authorization");
    expect(prefixInput()).toHaveValue("Token ");
    // The hint names both token forms (classic Token vs nbt_… Bearer).
    expect(screen.getByText(/nbt_/)).toBeInTheDocument();

    await userEvent.type(keyInput(), "abc123");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(mockedAdd).toHaveBeenCalledTimes(1));
    const sent = mockedAdd.mock.calls[0][0] as ApiSessionInput;
    expect(sent.kind).toBe("generic");
    expect(sent.vendor).toBe("netbox");
    expect(sent.base_url).toBe("https://netbox.lab/api");
    // The trailing space is load-bearing: `Authorization: Token <key>`.
    expect(sent.auth).toEqual({
      scheme: "api_key",
      header: "Authorization",
      value_prefix: "Token ",
    });
    expect(sent.secret).toEqual({ backend: "keyring", key: "transit/api-netbox-lab" });

    await waitFor(() => expect(mockedEnroll).toHaveBeenCalledWith("netbox-lab", "abc123"));
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  });

  it("a blank value prefix submits as the bare-key shape (back-compat)", async () => {
    renderWithQuery(<AddApiSessionDialog open onOpenChange={vi.fn()} />);

    await userEvent.type(idInput(), "swapi");
    await userEvent.type(nameInput(), "SWAPI");
    await userEvent.selectOptions(screen.getByDisplayValue("UniFi (Ubiquiti)"), "generic");
    await userEvent.type(baseUrlInput(), "https://swapi.dev/api");

    await userEvent.click(screen.getByRole("tab", { name: /authentication/i }));
    // Default scheme api_key with no preset: header X-API-KEY, empty prefix.
    expect(headerInput()).toHaveValue("X-API-KEY");
    expect(prefixInput()).toHaveValue("");
    await userEvent.type(keyInput(), "k3y");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(mockedAdd).toHaveBeenCalledTimes(1));
    const sent = mockedAdd.mock.calls[0][0] as ApiSessionInput;
    expect(sent.auth).toEqual({ scheme: "api_key", header: "X-API-KEY", value_prefix: "" });
  });
});
