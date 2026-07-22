import { memo, useCallback } from "react"
import { Braces, Loader2, Table as TableIcon } from "lucide-react"
import type { Header, Table } from "@tanstack/react-table"
import { BalanceHelpButton } from "@/components/balance-help"
import { KeyRow, type KeyRowProps } from "@/components/key-row"
import { colWidthStyle, type KeyColumnId } from "@/components/key-table-columns"
import { Checkbox } from "@/components/ui/checkbox"
import { cn } from "@/lib/utils"

const COLUMN_LABELS: Record<KeyColumnId, string> = {
  apikey: "APIKEY",
  endpoint: "APIURL / HOST",
  provider: "PROVIDER",
  balance: "BALANCE",
  createdAt: "入库时间",
  status: "STATUS",
}

/** A single resizable header cell with its drag grip on the right edge. */
function HeaderCell({ header }: Readonly<{ header: Header<unknown, unknown> }>) {
  const id = header.column.id as KeyColumnId
  const canResize = header.column.getCanResize()
  return (
    <span className="relative flex shrink-0 items-center gap-1 overflow-visible" style={colWidthStyle(id)}>
      <span className="truncate">{COLUMN_LABELS[id] ?? id}</span>
      {id === "balance" ? <BalanceHelpButton /> : null}
      {canResize ? (
        <span
          role="separator"
          aria-orientation="vertical"
          aria-label={`Resize ${COLUMN_LABELS[id] ?? id} column`}
          onMouseDown={header.getResizeHandler()}
          onTouchStart={header.getResizeHandler()}
          onDoubleClick={() => header.column.resetSize()}
          className="group absolute -right-3.5 top-0 z-10 flex h-full w-3.5 cursor-col-resize touch-none items-center justify-center select-none"
        >
          <span
            className={cn(
              "h-4 w-0.5 rounded-full transition-colors",
              "bg-border-primary group-hover:bg-accent",
              header.column.getIsResizing() && "bg-accent",
            )}
          />
        </span>
      ) : null}
    </span>
  )
}

/** Column-aligned table header matching the shared `KeyRow` layout. */
export function KeyTableHeader({ table }: Readonly<{ table: Table<unknown> }>) {
  return (
    <div className="flex min-w-max flex-nowrap items-center gap-3.5 border-b border-border-primary bg-surface-base px-4 py-2.5 font-mono text-[11px] font-semibold tracking-[0.4px] text-text-muted">
      <span className="size-4 shrink-0" aria-hidden />
      {table.getFlatHeaders().map((header) => (
        <HeaderCell key={header.id} header={header} />
      ))}
      {/* Keep actions immediately after STATUS — no flex-1/ml-auto spacer. */}
      <span className="shrink-0 whitespace-nowrap text-right">测试 / 操作</span>
    </div>
  )
}

interface ExportButtonProps {
  icon: React.ReactNode
  label: string
  onClick: () => void
  disabled?: boolean
}

function ExportButton({ icon, label, onClick, disabled }: Readonly<ExportButtonProps>) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1.5 rounded-sm border border-border-primary bg-surface-raised px-3 py-1.5 font-sans text-xs font-medium text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50"
    >
      {icon}
      {label}
    </button>
  )
}

export interface BulkBarProps {
  selectedCount: number
  total: number
  allChecked: boolean
  onToggleAll: (checked: boolean) => void
  onExportJson: () => void
  onExportCsv: () => void
  exporting?: boolean
  jsonLabel?: string
  csvLabel?: string
  actionLabel?: string
  onAction?: () => void
  actionPending?: boolean
}

export function BulkBar({
  selectedCount,
  total,
  allChecked,
  onToggleAll,
  onExportJson,
  onExportCsv,
  exporting,
  jsonLabel = "导出 JSON",
  csvLabel = "导出 CSV",
  actionLabel,
  onAction,
  actionPending,
}: Readonly<BulkBarProps>) {
  return (
    <div className="flex items-center gap-3.5 border-b border-border-subtle bg-surface-inset px-8 py-3">
      <div className="flex flex-1 items-center gap-2.5">
        <Checkbox
          checked={allChecked}
          onCheckedChange={(value) => onToggleAll(value === true)}
          disabled={total === 0}
          aria-label="Select all keys"
        />
        <span className="font-sans text-[13px] text-text-secondary">
          已选 {selectedCount} / {total}
        </span>
      </div>
      {actionLabel && onAction ? (
        <ExportButton
          icon={actionPending ? <Loader2 className="size-3.5 animate-spin" /> : null}
          label={actionLabel}
          onClick={onAction}
          disabled={actionPending || selectedCount === 0}
        />
      ) : null}
      <ExportButton
        icon={exporting ? <Loader2 className="size-3.5 animate-spin" /> : <Braces className="size-3.5" />}
        label={jsonLabel}
        onClick={onExportJson}
        disabled={exporting || total === 0}
      />
      <ExportButton
        icon={exporting ? <Loader2 className="size-3.5 animate-spin" /> : <TableIcon className="size-3.5" />}
        label={csvLabel}
        onClick={onExportCsv}
        disabled={exporting || total === 0}
      />
    </div>
  )
}

/**
 * Memoized wrapper around the shared `KeyRow` that binds per-row callbacks by
 * index, so the parent can pass stable handlers and avoid re-rendering every
 * row on each state change.
 */
export interface IndexedKeyRowProps
  extends Omit<
    KeyRowProps,
    "onSelectedChange" | "onExpandedChange" | "onReveal" | "onCopy" | "onLoadModels" | "onBalance" | "onChat" | "onPromote"
  > {
  index: number
  onSelectedChange?: (index: number, checked: boolean) => void
  onExpandedChange?: (index: number, expanded: boolean) => void
  onReveal?: (index: number) => void
  onCopy?: (index: number) => void
  onLoadModels?: (index: number) => void
  onBalance?: (index: number) => void
  onChat?: (index: number) => void
  onPromote?: (index: number) => void
}

export const IndexedKeyRow = memo(function IndexedKeyRow({
  index,
  onSelectedChange,
  onExpandedChange,
  onReveal,
  onCopy,
  onLoadModels,
  onBalance,
  onChat,
  onPromote,
  ...rest
}: Readonly<IndexedKeyRowProps>) {
  const handleSelected = useCallback(
    (checked: boolean) => onSelectedChange?.(index, checked),
    [onSelectedChange, index],
  )
  const handleExpanded = useCallback(
    (expanded: boolean) => onExpandedChange?.(index, expanded),
    [onExpandedChange, index],
  )
  const handleReveal = useCallback(() => onReveal?.(index), [onReveal, index])
  const handleCopy = useCallback(() => onCopy?.(index), [onCopy, index])
  const handleLoadModels = useCallback(() => onLoadModels?.(index), [onLoadModels, index])
  const handleBalance = useCallback(() => onBalance?.(index), [onBalance, index])
  const handleChat = useCallback(() => onChat?.(index), [onChat, index])
  const handlePromote = useCallback(() => onPromote?.(index), [onPromote, index])

  return (
    <KeyRow
      {...rest}
      onSelectedChange={onSelectedChange ? handleSelected : undefined}
      onExpandedChange={onExpandedChange ? handleExpanded : undefined}
      onReveal={onReveal ? handleReveal : undefined}
      onCopy={onCopy ? handleCopy : undefined}
      onLoadModels={onLoadModels ? handleLoadModels : undefined}
      onBalance={onBalance ? handleBalance : undefined}
      onChat={onChat ? handleChat : undefined}
      onPromote={onPromote ? handlePromote : undefined}
    />
  )
})

export function CenterState({ children, className }: Readonly<{ children: React.ReactNode; className?: string }>) {
  return (
    <div className={cn("flex flex-1 items-center justify-center px-8 py-16 text-sm text-text-muted", className)}>
      {children}
    </div>
  )
}
