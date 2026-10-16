import { describe, expect, it } from "vitest";

import { sequentialLaunch } from "@/lib/sequentialLaunch";

describe("sequentialLaunch", () => {
  it("runs strictly sequentially — never two in flight at once", async () => {
    let inFlight = 0;
    const order: string[] = [];
    const result = await sequentialLaunch({
      ids: ["a", "b", "c"],
      run: async (id) => {
        inFlight += 1;
        expect(inFlight).toBe(1); // the whole point: single-slot prompt safety
        order.push(id);
        await Promise.resolve();
        inFlight -= 1;
      },
    });
    expect(order).toEqual(["a", "b", "c"]);
    expect(result).toEqual({ opened: 3, failures: [], stopped: false, total: 3 });
  });

  it("continues past failures and aggregates them in launch order", async () => {
    const result = await sequentialLaunch({
      ids: ["ok1", "bad", "ok2"],
      run: async (id) => {
        if (id === "bad") throw new Error("nope");
      },
    });
    expect(result.opened).toBe(2);
    expect(result.failures).toEqual([{ id: "bad", message: "nope" }]);
    expect(result.stopped).toBe(false);
    expect(result.total).toBe(3);
  });

  it("stringifies a non-Error rejection rather than dropping it", async () => {
    const result = await sequentialLaunch({
      ids: ["x"],
      run: async () => {
        throw "raw string failure";
      },
    });
    expect(result.failures).toEqual([{ id: "x", message: "raw string failure" }]);
  });

  it("stops BEFORE the next launch when shouldStop returns true, leaving the rest unlaunched", async () => {
    const launched: string[] = [];
    let settled = 0;
    const result = await sequentialLaunch({
      ids: ["a", "b", "c"],
      run: async (id) => {
        launched.push(id);
      },
      // Stop once the first has settled (an in-flight invoke can't be aborted).
      shouldStop: () => settled >= 1,
      onProgress: () => {
        settled += 1;
      },
    });
    expect(launched).toEqual(["a"]);
    expect(result).toMatchObject({ opened: 1, stopped: true, total: 3 });
  });

  it("reports progress after each settle — success OR failure", async () => {
    const progress: Array<[number, number]> = [];
    await sequentialLaunch({
      ids: ["a", "bad"],
      run: async (id) => {
        if (id === "bad") throw new Error("x");
      },
      onProgress: (done, total) => progress.push([done, total]),
    });
    expect(progress).toEqual([
      [1, 2],
      [2, 2],
    ]);
  });
});
