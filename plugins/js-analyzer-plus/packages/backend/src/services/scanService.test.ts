import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SDK } from "caido:plugin";
import type { ScanResult } from "shared";
import type { API, BackendEvents } from "../index";
import { setSDK } from "../sdk";
import { startPassiveScan } from "./scanService";

vi.mock("./npmVerifier", () => ({ verifyPackagesOnNpm: vi.fn(async () => []) }));

const state = vi.hoisted(() => ({ results: [] as ScanResult[] }));
vi.mock("../stores", () => ({
  getScanResultsStore: () => ({ update: (fn: (results: ScanResult[]) => ScanResult[]) => { state.results = fn(state.results); } }),
  getConfigStore: () => ({ get: () => ({ allowNetworkRequests: false }) }),
}));

beforeEach(() => { state.results = []; });

describe("manual request scan", () => {
  it("returns and stores matches without writing any Findings", async () => {
    const create = vi.fn();
    const exists = vi.fn(async () => false);
    const sdk = {
      requests: { get: vi.fn(async () => ({
        request: { getUrl: () => 'https://app.test/main.js' },
        response: {
          getHeader: () => ['text/javascript'],
          getBody: () => ({ toText: () => 'fetch("/api/users"); const hash="aK9mZ3xQ7vB2nL5wR8jT4uY1cF6hG0eD";' }),
        },
      })) },
      findings: { create, exists },
      api: { send: vi.fn() },
    } as unknown as SDK<API, BackendEvents>;
    setSDK(sdk);
    const result = await startPassiveScan(['1'], ['apiEndpoints', 'secrets']);
    expect(result.status).toBe('Complete');
    expect(result.totalMatches).toBeGreaterThan(0);
    expect(result.entries.flatMap(e => e.matches).some(m => m.value.includes('High Entropy'))).toBe(true);
    expect(state.results).toHaveLength(1);
    expect(state.results[0]!.totalMatches).toBe(result.totalMatches);
    expect(create).not.toHaveBeenCalled();
    expect(exists).not.toHaveBeenCalled();
    expect(sdk.api.send).toHaveBeenCalledWith('scan-complete', expect.any(Object));
  });
});
