import type { ScanSource, ScanSourceItem } from "@/lib/api"

/** Multi-select sources on the main scan page (manual has a dedicated page). */
export const ALL_SCAN_SOURCES: readonly ScanSourceItem[] = ["fofa", "shodan", "github"]

/** Dedicated opt-in lanes not included in "all". */
export const DEDICATED_SCAN_SOURCES: readonly ScanSourceItem[] = ["manual"]

const KNOWN_SOURCES: readonly ScanSourceItem[] = [...ALL_SCAN_SOURCES, ...DEDICATED_SCAN_SOURCES]

function isKnownSource(value: string): value is ScanSourceItem {
  return (KNOWN_SOURCES as readonly string[]).includes(value)
}

export function parseSourceLabel(label: string | null | undefined): ScanSourceItem[] {
  if (!label || label === "all") return [...ALL_SCAN_SOURCES]
  return label
    .split(",")
    .map((value) => value.trim())
    .filter(isKnownSource)
}

export function toCanonicalSourceLabel(selected: readonly ScanSourceItem[]): string {
  if (selected.length === 0) return ""
  // Single dedicated source (e.g. manual) — never collapse to "all".
  if (selected.length === 1 && DEDICATED_SCAN_SOURCES.includes(selected[0])) {
    return selected[0]
  }
  if (
    selected.length === ALL_SCAN_SOURCES.length &&
    ALL_SCAN_SOURCES.every((source) => selected.includes(source))
  ) {
    return "all"
  }
  return selected.length === 1 ? selected[0] : [...selected].sort().join(",")
}

export function toggleSource(
  selected: readonly ScanSourceItem[],
  source: ScanSourceItem,
): ScanSourceItem[] {
  return selected.includes(source)
    ? selected.filter((item) => item !== source)
    : [...selected, source]
}

export function toggleAllSources(selected: readonly ScanSourceItem[]): ScanSourceItem[] {
  const allSelected = ALL_SCAN_SOURCES.every((source) => selected.includes(source))
  return allSelected ? [] : [...ALL_SCAN_SOURCES]
}

export function serializeSources(selected: readonly ScanSourceItem[]): {
  source: ScanSource
  sources: ScanSourceItem[]
} | null {
  // Dedicated single-source pages (manual) bypass the FOFA/Shodan/GitHub multi-select.
  if (selected.length === 1 && DEDICATED_SCAN_SOURCES.includes(selected[0])) {
    return { source: selected[0], sources: [selected[0]] }
  }
  const ordered = ALL_SCAN_SOURCES.filter((source) => selected.includes(source))
  if (ordered.length === 0) return null
  if (ordered.length === ALL_SCAN_SOURCES.length) return { source: "all", sources: [] }
  if (ordered.length === 1) return { source: ordered[0], sources: ordered }
  return { source: ordered[0], sources: ordered }
}
