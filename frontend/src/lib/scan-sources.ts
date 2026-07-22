import type { ScanSource, ScanSourceItem } from "@/lib/api"

export const ALL_SCAN_SOURCES: readonly ScanSourceItem[] = ["fofa", "shodan", "github"]

export function parseSourceLabel(label: string | null | undefined): ScanSourceItem[] {
  if (!label || label === "all") return [...ALL_SCAN_SOURCES]
  return label
    .split(",")
    .map((value) => value.trim())
    .filter((value): value is ScanSourceItem =>
      ALL_SCAN_SOURCES.includes(value as ScanSourceItem),
    )
}

export function toCanonicalSourceLabel(selected: readonly ScanSourceItem[]): string {
  if (selected.length === 0) return ""
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
  const ordered = ALL_SCAN_SOURCES.filter((source) => selected.includes(source))
  if (ordered.length === 0) return null
  if (ordered.length === ALL_SCAN_SOURCES.length) return { source: "all", sources: [] }
  if (ordered.length === 1) return { source: ordered[0], sources: ordered }
  return { source: ordered[0], sources: ordered }
}
