import { describe, expect, it } from "vitest";

import type { LocalEndpointStatus, LocalModelsStatus } from "@/lib/api";
import { isLocalModelId, mergeLocalPickerModels } from "@/lib/localModels";

describe("isLocalModelId", () => {
  it("mirrors transit_agent::llm::is_local_model", () => {
    expect(isLocalModelId("ollama:qwen3:8b")).toBe(true);
    expect(isLocalModelId("endpoint:lab-vllm/qwen3:8b")).toBe(true);
    expect(isLocalModelId("claude-opus-4-8")).toBe(false);
    expect(isLocalModelId("gpt-ollama-distill")).toBe(false);
    expect(isLocalModelId("ollama")).toBe(false);
  });
});

describe("mergeLocalPickerModels", () => {
  const status: LocalModelsStatus = {
    enabled: true,
    reachable: true,
    base_url: "http://127.0.0.1:11434",
    version: "0.32.1",
    version_supported: true,
    models: [
      { id: "ollama:qwen3:8b", name: "qwen3:8b", size_bytes: 5e9, tools_capable: true },
      { id: "ollama:notools", name: "notools", size_bytes: 1, tools_capable: false },
    ],
    hidden_cloud_models: ["glm-5:cloud"],
    error: null,
    warning: null,
  };
  const endpoints: LocalEndpointStatus[] = [
    {
      id: "lab",
      name: "Lab vLLM",
      kind: "openai_compat",
      reachable: true,
      error: null,
      models: [{ id: "endpoint:lab/qwen3-8b", name: "qwen3-8b", tools_capable: null }],
      hidden_cloud_models: [],
    },
    {
      id: "down",
      name: "Down",
      kind: "ollama",
      reachable: false,
      error: "cannot reach",
      models: [],
      hidden_cloud_models: [],
    },
  ];

  it("keeps tools-capable Ollama models and unverified endpoint models; drops the rest", () => {
    const merged = mergeLocalPickerModels(status, endpoints);
    expect(merged.map((m) => m.id)).toEqual(["ollama:qwen3:8b", "endpoint:lab/qwen3-8b"]);
    expect(merged[0]).toMatchObject({ label: "qwen3:8b · local", toolsVerified: true });
    // OpenAI-compat exposes no capability metadata → offered but
    // labeled unverified, never silently hidden.
    expect(merged[1]).toMatchObject({ label: "qwen3-8b · Lab vLLM", toolsVerified: false });
  });

  it("an unreachable zero-config Ollama contributes nothing", () => {
    const merged = mergeLocalPickerModels({ ...status, reachable: false }, endpoints);
    expect(merged.map((m) => m.id)).toEqual(["endpoint:lab/qwen3-8b"]);
  });

  it("handles undefined inputs (queries disabled)", () => {
    expect(mergeLocalPickerModels(undefined, undefined)).toEqual([]);
  });
});
