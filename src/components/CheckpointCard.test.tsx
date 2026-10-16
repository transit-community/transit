import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { CheckpointCard } from "@/components/CheckpointCard";

describe("CheckpointCard", () => {
  it("labels itself with rounds + tokens and never a dollar amount", () => {
    render(
      <CheckpointCard rounds={12} tokens={18243} onContinue={() => {}} onDismiss={() => {}} />,
    );
    const card = screen.getByTestId("checkpoint-card");
    expect(card.textContent).toMatch(/Paused after 12 commands \(18\.2k tokens\)/);
    expect(card.textContent).not.toContain("$");
  });

  it("singularizes 'command' at one round", () => {
    render(<CheckpointCard rounds={1} tokens={50} onContinue={() => {}} onDismiss={() => {}} />);
    expect(screen.getByTestId("checkpoint-card").textContent).toMatch(/Paused after 1 command \(/);
  });

  it("wires Continue and Stop to their callbacks", async () => {
    const onContinue = vi.fn();
    const onDismiss = vi.fn();
    render(
      <CheckpointCard rounds={3} tokens={100} onContinue={onContinue} onDismiss={onDismiss} />,
    );
    await userEvent.click(screen.getByTestId("checkpoint-continue"));
    expect(onContinue).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByTestId("checkpoint-stop"));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});
