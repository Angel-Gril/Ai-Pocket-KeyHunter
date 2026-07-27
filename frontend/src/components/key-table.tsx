import { memo, useCallback } from "react"
import { Download, Loader2 } from "lucide-react"
import type { Header, Table } from "@tanstack/react-table"
import { BalanceHelpButton } from "@/components/balance-help"
import { KeyRow, type KeyRowProps } from "@/components/key-row"
import { colWidthStyle, type KeyColumnId } from "@/components/key-table-columns"
import { Checkbox } from "@/components/ui/checkbox"
import { cn } from "@/lib/utils"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { ExportFormat } from "@/lib/api"

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
    <span
      className="relative flex shrink-0 items-center gap-1 overflow-visible"
      style={colWidthStyle(id)}
    >
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

/** Column-aligned table header using the shared computed column widths. */
export function KeyTableHeader({ table, actionWidth }: Readonly<{ table: Table<unknown>; actionWidth: number }>) {
  return (
    <div className="flex w-full min-w-max flex-nowrap items-center gap-3.5 border-b border-border-primary bg-surface-base px-4 py-2.5 font-mono text-[11px] font-semibold tracking-[0.4px] text-text-muted">
      <span className="size-4 shrink-0" aria-hidden />
      {table.getFlatHeaders().map((header) => (
        <HeaderCell key={header.id} header={header} />
      ))}
      {/* Match the page's widest row action cluster so all rows end together. */}
      <span className="shrink-0 whitespace-nowrap" style={{ width: actionWidth }}>测试 / 操作</span>
    </div>
  )
}

interface ActionButtonProps {
  icon: React.ReactNode
  label: string
  onClick: () => void
  disabled?: boolean
}

function ExportButton({ icon, label, onClick, disabled }: Readonly<ActionButtonProps>) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex min-h-11 items-center justify-center gap-1.5 rounded-sm border border-border-primary bg-surface-raised px-3 py-1.5 font-sans text-xs font-medium text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50 sm:min-h-0"
    >
      {icon}
      {label}
    </button>
  )
}

interface ExportMenuProps {
  onExport: (format: ExportFormat) => void
  disabled?: boolean
  exporting?: boolean
  label?: string
}

function ExportMenu({ onExport, disabled, exporting, label = "导出" }: Readonly<ExportMenuProps>) {
  return (
    <Select disabled={disabled || exporting} onValueChange={(value) => onExport(value as ExportFormat)}>
      <SelectTrigger className="min-h-11 w-[136px] border-border-primary bg-surface-raised font-sans text-xs font-medium text-text-secondary sm:min-h-0">
        {exporting ? <Loader2 className="size-3.5 animate-spin" /> : <Download className="size-3.5" />}
        <SelectValue placeholder={label} />
      </SelectTrigger>
      <SelectContent align="end">
        <SelectItem value="json">JSON</SelectItem>
        <SelectItem value="csv">CSV</SelectItem>
        <SelectItem value="sub2api">Sub2API</SelectItem>
      </SelectContent>
    </Select>
  )
}

export interface BulkBarProps {
  selectedCount: number
  total: number
  allChecked: boolean
  onToggleAll: (checked: boolean) => void
  onExport: (format: ExportFormat) => void
  exporting?: boolean
  exportLabel?: string
  actionLabel?: string
  onAction?: () => void
  actionPending?: boolean
}

export function BulkBar({
  selectedCount,
  total,
  allChecked,
  onToggleAll,
  onExport,
  exporting,
  exportLabel,
  actionLabel,
  onAction,
  actionPending,
}: Readonly<BulkBarProps>) {
  return (
    <div className="flex flex-wrap items-center gap-2.5 border-b border-border-subtle bg-surface-inset px-4 py-3 sm:flex-nowrap sm:gap-3.5 sm:px-6 md:px-8">
      <div className="flex min-w-full flex-1 items-center gap-2.5 sm:min-w-0">
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
      <ExportMenu
        onExport={onExport}
        exporting={exporting}
        disabled={total === 0}
        label={exportLabel}
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
    "onSelectedChange" | "onExpandedChange" | "onReveal" | "onCopy" | "onLoadModels" | "onBalance" | "onChat" | "onMarkValid" | "onMarkUnavailable" | "onMarkSuspicious"
  > {
  index: number
  onSelectedChange?: (index: number, checked: boolean) => void
  onExpandedChange?: (index: number, expanded: boolean) => void
  onReveal?: (index: number) => void
  onCopy?: (index: number) => void
  onLoadModels?: (index: number) => void
  onBalance?: (index: number) => void
  onChat?: (index: number) => void
  onMarkValid?: (index: number) => void
  onMarkUnavailable?: (index: number) => void
  onMarkSuspicious?: (index: number) => void
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
  onMarkValid,
  onMarkUnavailable,
  onMarkSuspicious,
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
  const handleMarkValid = useCallback(() => onMarkValid?.(index), [onMarkValid, index])
  const handleMarkUnavailable = useCallback(() => onMarkUnavailable?.(index), [onMarkUnavailable, index])
  const handleMarkSuspicious = useCallback(() => onMarkSuspicious?.(index), [onMarkSuspicious, index])

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
      onMarkValid={onMarkValid ? handleMarkValid : undefined}
      onMarkUnavailable={onMarkUnavailable ? handleMarkUnavailable : undefined}
      onMarkSuspicious={onMarkSuspicious ? handleMarkSuspicious : undefined}
    />
  )
})

export function CenterState({ children, className }: Readonly<{ children: React.ReactNode; className?: string }>) {
  return (
    <div className={cn("flex flex-1 items-center justify-center px-4 py-12 text-center text-sm text-text-muted sm:px-6 md:px-8 md:py-16", className)}>
      {children}
    </div>
  )
}
