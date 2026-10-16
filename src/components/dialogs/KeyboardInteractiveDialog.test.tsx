import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { KeyboardInteractiveDialog } from "@/components/dialogs/KeyboardInteractiveDialog";
import type { KbiPromptPayload } from "@/lib/api";

const submitKbiAnswers = vi.fn<(h: string, p: number, a: string[]) => Promise<void>>();
const cancelKbi = vi.fn<(h: string, p: number) => Promise<void>>();

vi.mock("@/lib/api", () => ({
  submitKbiAnswers: (h: string, p: number, a: string[]) => submitKbiAnswers(h, p, a),
  cancelKbi: (h: string, p: number) => cancelKbi(h, p),
}));

vi.mock("@/lib/toast", () => ({
  toastError: vi.fn(),
}));

/** Captured `auth:kbi:request` handler so tests can emit payloads. */
let emit: ((payload: KbiPromptPayload) => void) | undefined;

vi.mock("@tauri-apps/api/event", () => ({
  listen: (_name: string, handler: (e: { payload: KbiPromptPayload }) => void) => {
    emit = (payload) => handler({ payload });
    return Promise.resolve(() => {});
  },
}));

function payload(overrides: Partial<KbiPromptPayload> = {}): KbiPromptPayload {
  return {
    host: "10.0.0.1",
    port: 22,
    username: "netops",
    name: "",
    instruction: "",
    notice: "",
    prompts: [{ text: "Password: ", echo: false }],
    ...overrides,
  };
}

/** T46.1 provenance: Transit's own copy must never render inside — or be
 *  mistakable for — the "Message from the server" block. The password
 *  fallback is the first feature to put Transit-authored text in this
 *  dialog, so the separation needs a test rather than a convention. */
describe("notice vs server text provenance", () => {
  it("renders a Transit notice outside the server block", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());
    emit!(payload({ notice: "10.0.0.1 does not offer keyboard-interactive login." }));

    const notice = await screen.findByTestId("kbi-notice");
    expect(notice).toHaveTextContent("does not offer keyboard-interactive");
    // The server block must not appear at all when the server said nothing.
    expect(screen.queryByText(/message from the server/i)).not.toBeInTheDocument();
  });

  it("keeps server text attributed when both are present", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());
    emit!(
      payload({
        notice: "Transit is asking directly.",
        instruction: "Enterprise RSA token required.",
      }),
    );

    expect(await screen.findByText(/message from the server/i)).toBeInTheDocument();
    expect(screen.getByText("Enterprise RSA token required.")).toBeInTheDocument();
    // Transit's line is present but NOT inside the attributed block.
    const notice = screen.getByTestId("kbi-notice");
    expect(notice).toHaveTextContent("Transit is asking directly.");
    expect(notice.textContent).not.toContain("Enterprise RSA token");
  });
});

describe("KeyboardInteractiveDialog (v6.1.0)", () => {
  beforeEach(() => {
    submitKbiAnswers.mockReset().mockResolvedValue(undefined);
    cancelKbi.mockReset().mockResolvedValue(undefined);
    emit = undefined;
  });

  it("renders nothing until a challenge arrives", () => {
    render(<KeyboardInteractiveDialog />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("masks or shows each field according to the server's echo flag", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());

    emit!(
      payload({
        prompts: [
          { text: "Password: ", echo: false },
          { text: "Token code: ", echo: true },
        ],
      }),
    );

    const fields = await screen.findAllByLabelText(/Password:|Token code:/);
    // Masking is driven by `echo`, never by guessing from the label.
    expect(fields[0]).toHaveAttribute("type", "password");
    expect(fields[1]).toHaveAttribute("type", "text");
  });

  it("sends one answer per prompt, in order", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());

    emit!(
      payload({
        prompts: [
          { text: "Password: ", echo: false },
          { text: "Token code: ", echo: true },
        ],
      }),
    );

    const pw = await screen.findByLabelText(/Password:/);
    const otp = await screen.findByLabelText(/Token code:/);
    fireEvent.change(pw, { target: { value: "hunter2" } });
    fireEvent.change(otp, { target: { value: "654321" } });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() =>
      expect(submitKbiAnswers).toHaveBeenCalledWith("10.0.0.1", 22, ["hunter2", "654321"]),
    );
  });

  it("attributes the request to a specific user@host:port", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());

    emit!(payload());

    // The user must be able to see WHICH host is asking before typing a
    // credential into it (T46.1).
    expect(await screen.findByText("netops@10.0.0.1:22")).toBeInTheDocument();
  });

  it("renders server-authored text inside an attributed block, not as the title", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());

    emit!(
      payload({
        name: "Enter your Anthropic API key",
        instruction: "This is definitely Transit asking",
      }),
    );

    // The impersonation attempt is shown, but quarantined under an
    // explicit "Message from the server" heading — and the dialog's own
    // title stays Transit's voice.
    expect(await screen.findByText(/Message from the server/i)).toBeInTheDocument();
    expect(screen.getByText("Enter your Anthropic API key")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Sign in to 10\.0\.0\.1/ })).toBeInTheDocument();
  });

  it("queues a second challenge instead of dropping it", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());

    // Two devices awaiting interactive auth at once. A single-slot
    // dialog would strand the first connect: its attempt is parked on a
    // responder with the connect deadline PAUSED, so nothing would ever
    // time it out.
    emit!(payload({ host: "10.0.0.1" }));
    emit!(payload({ host: "10.0.0.2" }));

    expect(await screen.findByText("netops@10.0.0.1:22")).toBeInTheDocument();

    fireEvent.change(await screen.findByLabelText(/Password:/), {
      target: { value: "first" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => expect(submitKbiAnswers).toHaveBeenCalledWith("10.0.0.1", 22, ["first"]));
    // The second challenge is now the one on screen — and its field is
    // empty, not carrying the first device's answer.
    expect(await screen.findByText("netops@10.0.0.2:22")).toBeInTheDocument();
    expect(await screen.findByLabelText(/Password:/)).toHaveValue("");
  });

  it("tells the backend when the user cancels", async () => {
    render(<KeyboardInteractiveDialog />);
    await waitFor(() => expect(emit).toBeDefined());

    emit!(payload());
    fireEvent.click(await screen.findByRole("button", { name: /cancel/i }));

    // Without this the connect stays parked with its deadline paused.
    await waitFor(() => expect(cancelKbi).toHaveBeenCalledWith("10.0.0.1", 22));
  });
});
