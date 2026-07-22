import { useEffect, useMemo, useRef, useState } from "react"
import {
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnSizingState,
  type Table,
} from "@tanstack/react-table"
import { readColumnSizing, writeColumnSizing } from "@/lib/table-storage"

/**
 * The resizable data columns of the shared key table. The leading checkbox
 * spacer and trailing actions cell are laid out outside react-table.
 *
 * react-table is used ONLY for column-sizing state + resize handlers; we render
 * the header/rows ourselves, so `data` is empty and no accessors are needed.
 */
export const KEY_COLUMN_IDS = ["apikey", "endpoint", "provider", "balance", "createdAt", "status"] as const
export type KeyColumnId = (typeof KEY_COLUMN_IDS)[number]

export const KEY_COLUMNS: ColumnDef<unknown>[] = [
  { id: "apikey", size: 280, minSize: 160 },
  { id: "endpoint", size: 230, minSize: 140 },
  { id: "provider", size: 128, minSize: 96 },
  { id: "balance", size: 100, minSize: 80 },
  { id: "createdAt", size: 160, minSize: 130 },
  { id: "status", size: 110, minSize: 90 },
]

/** CSS custom property name carrying a column's current width (in px, unitless). */
export function colSizeVar(id: KeyColumnId): string {
  return `--col-${id}-size`
}
/** Fixed-width column driven by the shared computed sizing variables. */
export function colWidthStyle(id: KeyColumnId): React.CSSProperties {
  return { width: `calc(var(${colSizeVar(id)}) * 1px)` }
}

/** Every data cell is fixed to its computed shared width. */
export function colCellClass(_id: KeyColumnId): string {
  return "shrink-0"
}

/** Inline width for a data column. */
export function colStyle(id: KeyColumnId): React.CSSProperties {
  return colWidthStyle(id)
}


export interface KeyTableSizing {
  table: Table<unknown>
  /** `{ '--col-<id>-size': number }` map to spread onto the shared container. */
  columnSizeVars: Record<string, number>
  /** Attach to the scrollport so surplus width is folded into the shared sizes. */
  sizingContainerRef: React.RefObject<HTMLDivElement | null>
}

/**
 * Headless react-table instance dedicated to column sizing, seeded from and
 * persisted to localStorage. Returns the table (for header resize handles) plus
 * a CSS-variable map to spread onto the container that wraps the header + rows,
 * so widths propagate via inherited CSS vars — the memoized rows never re-render
 * on a drag frame.
 */
export function useKeyTableSizing(actionWidth = 280): KeyTableSizing {
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>(readColumnSizing)
  const [containerWidth, setContainerWidth] = useState(0)
  const sizingContainerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const element = sizingContainerRef.current
    if (!element) return
    const observer = new ResizeObserver(([entry]) => setContainerWidth(entry.contentRect.width))
    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  const table = useReactTable({
    data: EMPTY_DATA,
    columns: KEY_COLUMNS,
    state: { columnSizing },
    onColumnSizingChange: (updater) => {
      setColumnSizing((prev) => {
        const next = typeof updater === "function" ? updater(prev) : updater
        writeColumnSizing(next)
        return next
      })
    },
    enableColumnResizing: true,
    columnResizeMode: "onChange",
    getCoreRowModel: getCoreRowModel(),
  })

  const columnSizeVars = useMemo(() => {
    const headers = table.getFlatHeaders()
    // Fit the default schema to the viewport once, then add user drag deltas on
    // top. This keeps the action cluster visible without making one column fluid.
    const defaults = KEY_COLUMNS.map((column) => Number(column.size ?? 150))
    const minimums = KEY_COLUMNS.map((column) => Number(column.minSize ?? 20))
    const flexibleCount = headers.length - 1
    const defaultFlexibleTotal = defaults.slice(0, flexibleCount).reduce((sum, size) => sum + size, 0)
    const minimumFlexibleTotal = minimums.slice(0, flexibleCount).reduce((sum, size) => sum + size, 0)
    // 32px horizontal padding + 16px checkbox + seven 14px inter-cell gaps +
    // the current page's action cluster width.
    const chromeWidth = 146 + actionWidth
    const targetFlexibleTotal = Math.max(
      minimumFlexibleTotal,
      containerWidth - chromeWidth - defaults[headers.length - 1],
    )
    const shrinkRatio = Math.min(
      1,
      Math.max(0, defaultFlexibleTotal - targetFlexibleTotal) /
        (defaultFlexibleTotal - minimumFlexibleTotal),
    )
    const growRatio = Math.max(0, targetFlexibleTotal - defaultFlexibleTotal) / defaultFlexibleTotal
    const vars: Record<string, number> = {}
    headers.forEach((header, index) => {
      const baselineAdjustment = index < flexibleCount
        ? targetFlexibleTotal < defaultFlexibleTotal
          ? -(defaults[index] - minimums[index]) * shrinkRatio
          : defaults[index] * growRatio
        : 0
      vars[`--col-${header.column.id}-size`] = header.getSize() + baselineAdjustment
    })
    return vars
    // Recompute on committed sizing changes AND on live drag frames
    // (`columnSizingInfo` updates continuously in `onChange` resize mode).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [table, columnSizing, containerWidth, actionWidth, table.getState().columnSizingInfo])

  return { table, columnSizeVars, sizingContainerRef }
}

const EMPTY_DATA: unknown[] = []
