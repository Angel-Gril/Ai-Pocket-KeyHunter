import type { ColumnSizingState } from "@tanstack/react-table"

const COL_SIZES_KEY = "aipocket.key-table.col-sizes.v2"

/** Read the persisted key-table column widths, or `{}` when unset/unavailable. */
export function readColumnSizing(): ColumnSizingState {
  try {
    const raw = localStorage.getItem(COL_SIZES_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    // Guard against corrupted values: keep only numeric entries.
    if (!parsed || typeof parsed !== "object") return {}
    const out: ColumnSizingState = {}
    for (const [id, size] of Object.entries(parsed)) {
      if (typeof size === "number" && Number.isFinite(size)) out[id] = size
    }
    return out
  } catch {
    return {}
  }
}

/** Persist the key-table column widths. Silently no-ops when storage is unavailable. */
export function writeColumnSizing(sizing: ColumnSizingState): void {
  try {
    localStorage.setItem(COL_SIZES_KEY, JSON.stringify(sizing))
  } catch {
    /* storage unavailable — widths stay in memory for this session only */
  }
}
