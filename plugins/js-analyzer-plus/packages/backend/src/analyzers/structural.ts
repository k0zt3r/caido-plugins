import type { AnalyzerKind, AnalyzerMatch } from "shared";

import { analyze, MAX_BYTES } from "./local/analyzer.js";

const KINDS: Record<string, AnalyzerKind> = {
  route: "frameworkPatterns",
  secret: "secrets",
  email: "sensitiveData",
  storage: "sensitiveData",
  path: "apiEndpoints",
  http: "callPatterns",
  "http-expression": "stringExpressions",
  chunk: "chunkDiscovery",
  sourcemap: "inlineSourceMap",
};

/** Run on original source so nested routes and masked credentials keep exact source anchors. */
export function analyzeStructural(content: string, kinds: AnalyzerKind[]): AnalyzerMatch[] {
  if (content.length > MAX_BYTES || !Object.values(KINDS).some(kind => kinds.includes(kind))) return [];
  const result = analyze(content);
  return result.items.flatMap(item => {
    const kind = KINDS[item.kind];
    if (kind === undefined || !kinds.includes(kind)) return [];
    const start = item.offset;
    const token = content.slice(start).match(/^(["'`])(?:\\[\s\S]|(?!\1)[^\\])*?\1/);
    const end = Math.min(content.length, start + (token?.[0].length ?? 1));
    const value = item.kind === "route"
      ? `[AST ${item.analyzer}${result.hashRouting ? " hash route" : " route"}] ${result.hashRouting ? "#" : ""}${item.value}`
      : `[AST ${item.kind}] ${item.value}`;
    return [{
      analyzerKind: kind, value, startOffset: start, endOffset: end,
      rawStartOffset: start, rawEndOffset: end,
      confidence: item.kind === "route" ? "high" as const : "medium" as const,
      context: `Static candidate. ${item.note}. ${result.warnings.join("; ")}`,
    }];
  });
}
