import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ChatAutoApproveToggle } from "@/components/ChatAutoApproveToggle";
import type { ChatTab } from "@/stores/uiStore";

vi.mock("@/lib/api", () => ({
  chatSetAutoApproveGets: vi.fn().mockResolvedValue(undefined),
}));

afterEach(() => vi.clearAllMocks());

function tab(overrides: Partial<ChatTab>): ChatTab {
  return { chatId: "c", model: "m", seq: 1, scopedDeviceIds: null, ...overrides };
}

describe("ChatAutoApproveToggle", () => {
  it("renders nothing when auto-approve is off", () => {
    render(<ChatAutoApproveToggle chat={tab({ autoApproveGets: false })} />);
    expect(screen.queryByTestId("chat-auto-approve-toggle")).not.toBeInTheDocument();
  });

  it("renders nothing when autoApproveGets is undefined", () => {
    render(<ChatAutoApproveToggle chat={tab({})} />);
    expect(screen.queryByTestId("chat-auto-approve-toggle")).not.toBeInTheDocument();
  });

  it("shows the off-switch when on and turns auto-approve off on click", async () => {
    const { chatSetAutoApproveGets } = await import("@/lib/api");
    const mocked = vi.mocked(chatSetAutoApproveGets);
    render(<ChatAutoApproveToggle chat={tab({ chatId: "chatX", autoApproveGets: true })} />);
    const pill = screen.getByTestId("chat-auto-approve-toggle");
    expect(pill).toBeInTheDocument();
    await userEvent.click(pill);
    // Off-switch: the ONLY value it ever sends is false (turn per-call back on).
    expect(mocked).toHaveBeenCalledWith("chatX", false);
  });
});
