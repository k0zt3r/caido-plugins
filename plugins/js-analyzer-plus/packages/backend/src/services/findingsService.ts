import type { SDK } from "caido:plugin";
import type { Request } from "caido:utils";
import { findingDedupeKey, groupFindings, groupedFindingTitle, findingDescription, type AnalyzerMatch } from "shared";

import type { API, BackendEvents } from "../index";

export async function reportFindings(
  sdk: SDK<API, BackendEvents>,
  request: Request,
  matches: AnalyzerMatch[],
): Promise<void> {
  for (const match of groupFindings(matches)) {
    const dedupeKey = findingDedupeKey(request.getUrl(), match.analyzerKind, match.value);
    if (await sdk.findings.exists(dedupeKey)) continue;
    await sdk.findings.create({
      request,
      reporter: "JS Analyzer Plus",
      title: groupedFindingTitle(match) ?? `JS Analyzer Plus: ${match.analyzerKind}`,
      description: findingDescription(match, request.getUrl()),
      dedupeKey,
    });
  }
}
