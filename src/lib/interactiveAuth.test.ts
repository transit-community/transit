import { describe, expect, it } from "vitest";

import type { AuthProfileMeta, DeviceMeta } from "@/lib/api";
import {
  countLaunchable,
  interactiveSkipMessage,
  partitionInteractiveAuth,
} from "@/lib/interactiveAuth";

function device(id: string, auth: string): DeviceMeta {
  return {
    id,
    host: `${id}.example.net`,
    port: 22,
    vendor: "junos",
    auth,
  } as DeviceMeta;
}

function profile(name: string, backend: string): AuthProfileMeta {
  return { name, username: "op", backend, key_path: null };
}

describe("partitionInteractiveAuth (v6.1.0)", () => {
  it("holds back devices whose profile asks at connect time", () => {
    const devices = [device("r1", "stored"), device("fw1", "mfa"), device("r2", "stored")];
    const profiles = [profile("stored", "keyring"), profile("mfa", "prompt")];

    const { launchable, interactive } = partitionInteractiveAuth(devices, profiles);

    expect(launchable.map((d) => d.id)).toEqual(["r1", "r2"]);
    expect(interactive.map((d) => d.id)).toEqual(["fw1"]);
  });

  it("leaves a batch untouched when no profile is interactive", () => {
    const devices = [device("r1", "stored"), device("r2", "agent")];
    const profiles = [profile("stored", "keyring"), profile("agent", "ssh_agent")];

    const { launchable, interactive } = partitionInteractiveAuth(devices, profiles);

    expect(launchable).toHaveLength(2);
    expect(interactive).toHaveLength(0);
  });

  it("treats an unknown profile as launchable rather than silently dropping it", () => {
    // An unresolvable profile is the backend's error to report with a
    // real message — dropping it from the batch would hide the problem.
    const devices = [device("r1", "does-not-exist")];
    const { launchable, interactive } = partitionInteractiveAuth(devices, [
      profile("mfa", "prompt"),
    ]);

    expect(launchable.map((d) => d.id)).toEqual(["r1"]);
    expect(interactive).toHaveLength(0);
  });

  it("is a no-op while the profile list is still loading", () => {
    const devices = [device("r1", "mfa")];
    expect(partitionInteractiveAuth(devices, undefined).launchable).toHaveLength(1);
    expect(partitionInteractiveAuth(devices, []).launchable).toHaveLength(1);
  });

  it("holds back every device when the whole selection is interactive", () => {
    const devices = [device("fw1", "mfa"), device("fw2", "mfa")];
    const { launchable, interactive } = partitionInteractiveAuth(devices, [
      profile("mfa", "prompt"),
    ]);

    expect(launchable).toHaveLength(0);
    expect(interactive).toHaveLength(2);
  });
});

describe("interactiveSkipMessage", () => {
  it("names a single device", () => {
    expect(interactiveSkipMessage([device("fw1", "mfa")])).toContain("fw1");
    expect(interactiveSkipMessage([device("fw1", "mfa")])).toContain("on its own");
  });

  it("summarizes a long list without dumping every name", () => {
    const many = ["a", "b", "c", "d", "e"].map((id) => device(id, "mfa"));
    const msg = interactiveSkipMessage(many);

    expect(msg).toContain("5 devices");
    expect(msg).toContain("and 2 more");
    expect(msg).not.toContain("e.example.net");
  });
});

describe("countLaunchable", () => {
  it("counts only what a bulk launch will open", () => {
    // The bug this pins: a group of 9 where one device needs interactive
    // sign-in must offer "Launch all (8 devices)", not 9. The menu has to
    // promise what the action does.
    const devices = [
      ...["r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"].map((id) => device(id, "stored")),
      device("r8-int", "ask-me"),
    ];
    expect(devices).toHaveLength(9);
    expect(countLaunchable(devices, new Set(["ask-me"]))).toBe(8);
  });

  it("counts everything when no profile is interactive", () => {
    const devices = [device("r1", "stored"), device("r2", "stored")];
    expect(countLaunchable(devices, new Set())).toBe(2);
  });

  it("reaches zero when the whole selection needs a prompt", () => {
    const devices = [device("fw1", "ask-me"), device("fw2", "ask-me")];
    expect(countLaunchable(devices, new Set(["ask-me"]))).toBe(0);
  });
});
