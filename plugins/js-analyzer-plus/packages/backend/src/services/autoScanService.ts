import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";

import { scanSingleFile } from "../analyzers/runPassiveScan";
import { isStaticAsset } from "../constants";
import type { API, BackendEvents } from "../index";
import { getConfigStore } from "../stores";

import { reportFindings } from "./findingsService";

export function registerAutoScan(sdk: SDK<API, BackendEvents>): void {
  sdk.events.onInterceptResponse(async (eventSdk, request, response) => {
    try {
      await scanInterceptedResponse(eventSdk, request, response);
    } catch (err) {
      eventSdk.console.error(`JS Analyzer Plus passive scan failed: ${err}`);
    }
  });
}

export async function scanInterceptedResponse(
  sdk: SDK<API, BackendEvents>,
  request: Request,
  response: Response,
): Promise<void> {
  const config = getConfigStore().get();
  if (!config.autoScanEnabled || config.enabledAnalyzers.length === 0) return;
  if (config.inScopeOnly && !sdk.requests.inScope(request)) return;

  const url = request.getUrl();
  const contentType = response.getHeader("content-type")?.[0] ?? "";
  if (!isStaticAsset(contentType, url)) return;
  const content = response.getBody()?.toText();
  if (!content || content.length > 6 * 1024 * 1024) return;

  // Use the intercepted response directly: it may not be in history yet.
  // No requests are sent, including npm verification or discovered routes.
  const matches = scanSingleFile(
    { requestId: request.getId(), url, content },
    config.enabledAnalyzers,
    false,
  );
  await reportFindings(sdk, request, matches);
}
