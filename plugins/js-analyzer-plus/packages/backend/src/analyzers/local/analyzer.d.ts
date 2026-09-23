export const MAX_BYTES: number;
export type LocalItem = {kind: string; value: string; offset: number; analyzer: string; note: string};
export function analyze(source: string): {frameworks: string[]; items: LocalItem[]; warnings: string[]; parser: string; hashRouting: boolean};
