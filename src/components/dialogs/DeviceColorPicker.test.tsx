import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { DEVICE_COLORS } from "@/lib/deviceColors";

import { DeviceColorPicker } from "./DeviceColorPicker";

describe("DeviceColorPicker", () => {
  it("renders None + one swatch per palette color + Custom (v6.3.0)", () => {
    render(<DeviceColorPicker value="" onChange={vi.fn()} />);
    expect(screen.getAllByRole("radio")).toHaveLength(DEVICE_COLORS.length + 2);
    expect(screen.getByRole("radio", { name: "No color" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Blue" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Custom color" })).toBeInTheDocument();
  });

  it("marks the None option checked when value is empty", () => {
    render(<DeviceColorPicker value="" onChange={vi.fn()} />);
    expect(screen.getByRole("radio", { name: "No color" })).toHaveAttribute("aria-checked", "true");
  });

  it("marks the matching swatch checked when a token is selected", () => {
    render(<DeviceColorPicker value="red" onChange={vi.fn()} />);
    expect(screen.getByRole("radio", { name: "Red" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("radio", { name: "No color" })).toHaveAttribute(
      "aria-checked",
      "false",
    );
  });

  it("calls onChange with the token when a swatch is clicked", async () => {
    const onChange = vi.fn();
    render(<DeviceColorPicker value="" onChange={onChange} />);
    await userEvent.click(screen.getByRole("radio", { name: "Green" }));
    expect(onChange).toHaveBeenCalledWith("green");
  });

  it("calls onChange with an empty string when None is clicked", async () => {
    const onChange = vi.fn();
    render(<DeviceColorPicker value="red" onChange={onChange} />);
    await userEvent.click(screen.getByRole("radio", { name: "No color" }));
    expect(onChange).toHaveBeenCalledWith("");
  });

  it("marks Custom checked for a hex value and shows the hex readout (v6.3.0)", () => {
    render(<DeviceColorPicker value="#FFAA00" onChange={vi.fn()} />);
    const custom = screen.getByRole("radio", { name: "Custom color" });
    expect(custom).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("radio", { name: "No color" })).toHaveAttribute(
      "aria-checked",
      "false",
    );
    // Normalized-lowercase readout beside the swatch row.
    expect(screen.getByText("#ffaa00")).toBeInTheDocument();
  });

  it("propagates the native color input's value as lowercase hex", () => {
    const onChange = vi.fn();
    render(<DeviceColorPicker value="" onChange={onChange} />);
    const input = screen.getByTestId("device-color-custom-input");
    // `<input type=color>` only ever emits strict #rrggbb — simulate the
    // native change directly (the swatch button just proxies a click).
    fireEvent.change(input, { target: { value: "#00FF7F" } });
    expect(onChange).toHaveBeenCalledWith("#00ff7f");
  });

  it("a token selection leaves Custom unchecked", () => {
    render(<DeviceColorPicker value="green" onChange={vi.fn()} />);
    expect(screen.getByRole("radio", { name: "Custom color" })).toHaveAttribute(
      "aria-checked",
      "false",
    );
  });

  it("activating Custom commits the default hex immediately", async () => {
    // `<input type=color>` fires no change event when the user confirms
    // its pre-set value, so the default must be committed on activation
    // or picking exactly the default blue silently does nothing.
    const onChange = vi.fn();
    render(<DeviceColorPicker value="" onChange={onChange} />);
    await userEvent.click(screen.getByRole("radio", { name: "Custom color" }));
    expect(onChange).toHaveBeenCalledWith("#3b82f6");
  });

  it("re-clicking an active Custom swatch does not re-fire onChange", async () => {
    const onChange = vi.fn();
    render(<DeviceColorPicker value="#ffaa00" onChange={onChange} />);
    await userEvent.click(screen.getByRole("radio", { name: "Custom color" }));
    expect(onChange).not.toHaveBeenCalled();
  });
});
