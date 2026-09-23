// Independent of history request IDs, so revisiting the same asset deduplicates.
export function findingDedupeKey(url: string, kind: string, value: string): string {
  return `js-analyzer-plus:${JSON.stringify([url, kind, value])}`;
}
