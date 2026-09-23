import type { SDK } from "caido:plugin";
import type { Request } from "caido:utils";
import { findingDedupeKey, type AnalyzerMatch } from "shared";

import type { API, BackendEvents } from "../index";

export async function reportFindings(
  sdk: SDK<API, BackendEvents>,
  request: Request,
  matches: AnalyzerMatch[],
): Promise<void> {
  for (const match of matches) {
    const dedupeKey = findingDedupeKey(request.getUrl(), match.analyzerKind, match.value);
    if (await sdk.findings.exists(dedupeKey)) continue;
    await sdk.findings.create({
      request,
      reporter: "JS Analyzer Plus",
      title: `JS Analyzer Plus: ${match.analyzerKind}`,
      description: [
        `Source: ${request.getUrl()}`,
        `Confidence: ${match.confidence} (candidate; requires review)`,
        `Value: ${match.value.slice(0, 2000)}`,
        `Context: ${match.context.slice(0, 1000)}`,
      ].join("\n\n"),
      dedupeKey,
    });
  }
}
