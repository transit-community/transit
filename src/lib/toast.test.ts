import { describe, expect, it, vi } from "vitest";

vi.mock("sonner", () => {
  const fn = vi.fn();
  const promise = vi.fn();
  const toastFn = Object.assign(fn, {
    success: vi.fn(),
    error: vi.fn(),
    promise,
  });
  return { toast: toastFn };
});

import { toast as mockedToast } from "sonner";

import { toastError, toastInfo, toastPromise, toastSuccess } from "./toast";

describe("toast helpers", () => {
  it("toastSuccess defaults to 4s duration", () => {
    toastSuccess("Saved");
    expect(vi.mocked(mockedToast.success)).toHaveBeenCalledWith("Saved", { duration: 4000 });
  });

  it("toastError defaults to Infinity duration (manual dismiss)", () => {
    toastError("Connect failed");
    expect(vi.mocked(mockedToast.error)).toHaveBeenCalledWith("Connect failed", {
      duration: Infinity,
    });
  });

  it("toastInfo defaults to 5s duration", () => {
    toastInfo("Welcome back");
    expect(vi.mocked(mockedToast)).toHaveBeenCalledWith("Welcome back", { duration: 5000 });
  });

  it("opts override the defaults", () => {
    toastSuccess("Saved", { duration: 1000, description: "to disk" });
    expect(vi.mocked(mockedToast.success)).toHaveBeenCalledWith("Saved", {
      duration: 1000,
      description: "to disk",
    });
  });

  it("toastPromise forwards labels to sonner.promise + returns the original promise", async () => {
    const promise = Promise.resolve(42);
    const result = toastPromise(promise, {
      loading: "Working...",
      success: "Done",
      error: "Failed",
    });
    expect(vi.mocked(mockedToast.promise)).toHaveBeenCalledWith(promise, {
      loading: "Working...",
      success: "Done",
      error: "Failed",
    });
    expect(await result).toBe(42);
  });
});
