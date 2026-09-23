import { describe, expect, it, vi } from "vitest";
import type { SDK } from "caido:plugin";
import type { Request } from "caido:utils";
import { groupFindings, type AnalyzerMatch } from "shared";
import { reportFindings } from "./findingsService";
import type { API, BackendEvents } from "../index";

function route(path: string): AnalyzerMatch {
  return { analyzerKind: 'frameworkPatterns', value: `[AST Angular hash route] #/${path}`,
    startOffset: 1, endOffset: 2, rawStartOffset: 1, rawEndOffset: 2,
    confidence: 'high', context: '' };
}

describe('route Findings summaries', () => {
  it('publishes 240 routes as one complete finding and deduplicates reordered visits', async () => {
    const keys = new Set<string>();
    const create = vi.fn(async (spec) => { keys.add(spec.dedupeKey); return {}; });
    const sdk = { findings: { exists: async (key: string) => keys.has(key), create } } as unknown as SDK<API, BackendEvents>;
    const request = { getUrl: () => 'https://app.test/main.js' } as Request;
    const matches = Array.from({length: 240}, (_, i) => route(`admin/route-${i}`));
    await reportFindings(sdk, request, matches);
    expect(create).toHaveBeenCalledTimes(1);
    const spec = create.mock.calls[0]![0];
    expect(spec.title).toContain('240 routes');
    for (let i = 0; i < 240; i++) expect(spec.description).toContain(`#/admin/route-${i}`);
    await reportFindings(sdk, request, [...matches].reverse());
    expect(create).toHaveBeenCalledTimes(1);
    await reportFindings(sdk, { getUrl: () => 'https://other.test/main.js' } as Request, matches);
    expect(create).toHaveBeenCalledTimes(2);
  });

  it('deduplicates paths and preserves non-route findings', () => {
    const secret = { ...route('unused'), analyzerKind: 'secrets' as const, value: '[AST secret] password' };
    const result = groupFindings([route('admin'), route('admin'), route('login'), secret]);
    expect(result).toHaveLength(2);
    expect(result).toContain(secret);
    expect(result.find(m => m.findingSummary)?.findingSummary?.paths).toEqual(['#/admin', '#/login']);
  });
});

describe('API endpoint summaries', () => {
  it('groups AST and regex paths into one sorted Markdown list without truncation', async () => {
    const create = vi.fn(async (_spec) => ({}));
    const sdk = { findings: { exists: async () => false, create } } as unknown as SDK<API, BackendEvents>;
    const request = { getUrl: () => 'https://app.test/main.js' } as Request;
    const matches = Array.from({length: 240}, (_, i) => ({ ...route(''), analyzerKind: 'apiEndpoints' as const, value: `/api/users/${i}` }));
    matches.push({ ...matches[0]!, value: '[AST path] /api/users/0' });
    await reportFindings(sdk, request, [...matches, route('admin')]);
    expect(create).toHaveBeenCalledTimes(2);
    const spec = create.mock.calls.map(([spec]) => spec).find(spec => spec.title.includes('API endpoints'));
    expect(spec.title).toContain('240 endpoints');
    expect(spec.description.match(/^- /gm)).toHaveLength(240);
    for (let i = 0; i < 240; i++) expect(spec.description).toContain(`- \` /api/users/${i} \``);
    expect(spec.description).not.toContain('[AST path]');
    const routes = create.mock.calls.map(([spec]) => spec).find(spec => spec.title.includes('hash route'));
    expect(routes.description).toContain('- ` #/admin `');
  });
});
