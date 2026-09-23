import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";
import { ALL_ANALYZER_KINDS, type UserConfig } from "shared";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { API, BackendEvents } from "../index";
import { registerAutoScan, scanInterceptedResponse } from "./autoScanService";

const state = vi.hoisted(() => ({ config: {} as UserConfig }));
vi.mock("../stores", () => ({ getConfigStore: () => ({ get: () => state.config }) }));

function fixture(url = "https://example.test/app.js", contentType = "text/javascript") {
  const saved = new Set<string>();
  const create = vi.fn(async (spec) => { saved.add(spec.dedupeKey); return {}; });
  const sdk = {
    findings: { exists: vi.fn(async (key) => saved.has(key)), create },
    requests: { inScope: vi.fn(() => true) },
    console: { error: vi.fn() },
    events: { onInterceptResponse: vi.fn() },
  } as unknown as SDK<API, BackendEvents>;
  const request = { getUrl: () => url, getId: () => "123" } as unknown as Request;
  const response = {
    getHeader: () => [contentType],
    getBody: () => ({ toText: () => 'fetch("/api/private/users");' }),
  } as unknown as Response;
  return { sdk, request, response, create };
}

beforeEach(() => {
  state.config = { autoScanEnabled: true, inScopeOnly: false, allowNetworkRequests: false, enabledAnalyzers: ALL_ANALYZER_KINDS };
});

describe("automatic passive scan", () => {
  it.each([
    ["https://example.test/app.js", "text/javascript"],
    ["https://example.test/app.mjs", "text/plain"],
    ["https://example.test/app.cjs", "text/plain"],
    ["https://example.test/bundle?id=1", "application/javascript"],
  ])("reports intercepted asset %s without fetching history or sending requests", async (url, contentType) => {
    const { sdk, request, response, create } = fixture(url, contentType);
    await scanInterceptedResponse(sdk, request, response);
    expect(create).toHaveBeenCalled();
    expect(create.mock.calls[0]![0]).toMatchObject({ request, reporter: "JS Analyzer Plus" });
    const count = create.mock.calls.length;
    await scanInterceptedResponse(sdk, { ...request, getId: () => "456" } as Request, response);
    expect(create).toHaveBeenCalledTimes(count);
  });

  it("does not automatically publish entropy matches", async () => {
    const { sdk, request, response, create } = fixture();
    const noisyResponse = { ...response, getBody: () => ({
      toText: () => 'const hash = "aK9mZ3xQ7vB2nL5wR8jT4uY1cF6hG0eD"; fetch("/api/users");',
    }) } as unknown as Response;
    await scanInterceptedResponse(sdk, request, noisyResponse);
    expect(create).toHaveBeenCalled();
    expect(create.mock.calls.every(([spec]) => !spec.description.includes('High Entropy'))).toBe(true);
  });

  it("honors disabled scanning and scope", async () => {
    const { sdk, request, response, create } = fixture();
    state.config.autoScanEnabled = false;
    await scanInterceptedResponse(sdk, request, response);
    state.config.autoScanEnabled = true;
    state.config.inScopeOnly = true;
    vi.mocked(sdk.requests.inScope).mockReturnValue(false);
    await scanInterceptedResponse(sdk, request, response);
    expect(create).not.toHaveBeenCalled();
  });

  it("skips unrelated and empty responses", async () => {
    const { sdk, request, response, create } = fixture("https://example.test/image.png", "image/png");
    await scanInterceptedResponse(sdk, request, response);
    const js = fixture();
    await scanInterceptedResponse(sdk, js.request, { ...js.response, getBody: () => undefined } as Response);
    expect(create).not.toHaveBeenCalled();
  });

  it("registers a working callback and logs a failing findings write", async () => {
    const { sdk, request, response, create } = fixture();
    registerAutoScan(sdk);
    const callback = vi.mocked(sdk.events.onInterceptResponse).mock.calls[0]![0];
    create.mockRejectedValueOnce(new Error("write failed"));
    await callback(sdk, request, response);
    expect(sdk.console.error).toHaveBeenCalledWith(expect.stringContaining("write failed"));
  });
});
