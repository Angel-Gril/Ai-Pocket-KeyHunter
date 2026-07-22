import { useMemo, useState } from "react"
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

/**
 * Column that absorbs free row width on wide viewports so the table can be
 * `min-w-full` without leaving a dead strip after the actions column.
 * Resize still works: the handle adjusts this floor via `minWidth`.
 */
export const FLUID_COLUMN_ID: KeyColumnId = "endpoint"

/** Fixed-width column (shrink-0). */
export function colWidthStyle(id: KeyColumnId): React.CSSProperties {
  return { width: `calc(var(${colSizeVar(id)}) * 1px)` }
}

/** Fluid column: grow into free space, never below the sized min width. */
export function colFluidStyle(id: KeyColumnId): React.CSSProperties {
  return { minWidth: `calc(var(${colSizeVar(id)}) * 1px)` }
}

/** Shared cell layout class for a data column (fixed vs fluid). */
export function colCellClass(id: KeyColumnId): string {
  return id === FLUID_COLUMN_ID ? "min-w-0 flex-1" : "shrink-0"
}

/** Inline width/minWidth for a data column. */
export function colStyle(id: KeyColumnId): React.CSSProperties {
  return id === FLUID_COLUMN_ID ? colFluidStyle(id) : colWidthStyle(id)
}

export interface KeyTableSizing {
  table: Table<unknown>
  /** `{ '--col-<id>-size': number }` map to spread onto the shared container. */
  columnSizeVars: Record<string, number>
}

/**
 * Headless react-table instance dedicated to column sizing, seeded from and
 * persisted to localStorage. Returns the table (for header resize handles) plus
 * a CSS-variable map to spread onto the container that wraps the header + rows,
 * so widths propagate via inherited CSS vars — the memoized rows never re-render
 * on a drag frame.
 */
export function useKeyTableSizing(): KeyTableSizing {
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>(readColumnSizing)

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
    const vars: Record<string, number> = {}
    for (const header of table.getFlatHeaders()) {
      vars[`--col-${header.column.id}-size`] = header.getSize()
    }
    return vars
    // Recompute on committed sizing changes AND on live drag frames
    // (`columnSizingInfo` updates continuously in `onChange` resize mode).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [table, columnSizing, table.getState().columnSizingInfo])

  return { table, columnSizeVars }
}

const EMPTY_DATA: unknown[] = []
