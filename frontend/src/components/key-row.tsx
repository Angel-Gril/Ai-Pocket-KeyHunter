import { useState } from "react"
import { ChevronDown, Copy, Eye, EyeOff, List, Loader2, MessageSquare, Wallet } from "lucide-react"
import { Checkbox } from "@/components/ui/checkbox"
import { ProviderBadge } from "@/components/provider-badge"
import { colWidthStyle } from "@/components/key-table-columns"
import { StatusBadge, type StatusVariant } from "@/components/status-badge"
import { cn } from "@/lib/utils"

export interface KeyRowStatus {
  variant: StatusVariant
  label: string
}

export interface KeyRowProps {
  maskedKey: string
  revealedKey?: string
  apiurl?: string
  host?: string
  provider?: string
  balance?: string
  tier?: string
  credentialKind?: string
  validationState?: string
  scope?: string
  tierEvidence?: string
  status?: KeyRowStatus
  models?: string[]
  modelsLoading?: boolean
  selected?: boolean
  onSelectedChange?: (checked: boolean) => void
  expanded?: boolean
  onExpandedChange?: (expanded: boolean) => void
  onReveal?: () => void
  onCopy?: () => void
  onLoadModels?: () => void
  onBalance?: () => void
  onChat?: () => void
  busy?: { models?: boolean; balance?: boolean; chat?: boolean }
  className?: string
}

interface ActionButtonProps {
  icon: React.ReactNode
  label: string
  onClick?: () => void
  loading?: boolean
}

function ActionButton({ icon, label, onClick, loading }: Readonly<ActionButtonProps>) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center gap-1.5 rounded-sm border border-border-primary bg-surface-overlay px-2.5 py-1.5 font-sans text-xs font-medium text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50"
    >
      {loading ? <Loader2 className="size-3.5 animate-spin" /> : icon}
      {label}
    </button>
  )
}

const ICON_BUTTON =
  "flex size-[26px] shrink-0 items-center justify-center rounded-sm bg-surface-overlay text-text-muted hover:text-text-primary"

/** APIKEY cell: masked value + optional reveal/copy actions. */
function KeyCell({
  maskedKey,
  revealedKey,
  onReveal,
  onCopy,
}: Readonly<Pick<KeyRowProps, "maskedKey" | "revealedKey" | "onReveal" | "onCopy">>) {
  const [revealed, setRevealed] = useState(false)
  // The plaintext only exists once the parent has fetched it; stay masked until then.
  const canShowPlaintext = revealed && Boolean(revealedKey)
  const value = canShowPlaintext ? revealedKey! : maskedKey

  const toggleReveal = () => {
    const next = !canShowPlaintext
    if (next) onReveal?.()
    setRevealed(next)
  }

  return (
    <div className="flex shrink-0 items-center gap-2" style={colWidthStyle("apikey")}>
      {onReveal ? (
        <button
          type="button"
          onClick={toggleReveal}
          title={canShowPlaintext ? "Hide key" : "Reveal key"}
          className="min-w-0 truncate font-mono text-[13px] text-text-primary hover:text-accent"
        >
          {value}
        </button>
      ) : (
        <span className="min-w-0 truncate font-mono text-[13px] text-text-primary">{value}</span>
      )}
      {onReveal ? (
        <button
          type="button"
          onClick={toggleReveal}
          aria-label={canShowPlaintext ? "Hide key" : "Reveal key"}
          aria-pressed={canShowPlaintext}
          className={ICON_BUTTON}
        >
          {canShowPlaintext ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
        </button>
      ) : null}
      {onCopy ? (
        <button type="button" onClick={onCopy} aria-label="Copy key" className={ICON_BUTTON}>
          <Copy className="size-3.5" />
        </button>
      ) : null}
    </div>
  )
}

interface RowActionsProps {
  onLoadModels?: () => void
  onBalance?: () => void
  onChat?: () => void
  busy?: KeyRowProps["busy"]
  canExpand: boolean
  isExpanded: boolean
  onToggleExpand: () => void
}

/** Right-aligned per-row actions: models / balance / chat / expand. */
function RowActions({
  onLoadModels,
  onBalance,
  onChat,
  busy,
  canExpand,
  isExpanded,
  onToggleExpand,
}: Readonly<RowActionsProps>) {
  return (
    <div className="flex flex-1 items-center justify-end gap-1.5">
      {onLoadModels ? (
        <ActionButton icon={<List className="size-3.5" />} label="模型列表" onClick={onLoadModels} loading={busy?.models} />
      ) : null}
      {onBalance ? (
        <ActionButton icon={<Wallet className="size-3.5" />} label="余额" onClick={onBalance} loading={busy?.balance} />
      ) : null}
      {onChat ? (
        <ActionButton icon={<MessageSquare className="size-3.5" />} label="测对话" onClick={onChat} loading={busy?.chat} />
      ) : null}
      {canExpand ? (
        <button
          type="button"
          onClick={onToggleExpand}
          aria-label={isExpanded ? "Collapse models" : "Expand models"}
          aria-expanded={isExpanded}
          className="flex size-7 items-center justify-center rounded-sm bg-surface-overlay text-text-muted hover:text-text-primary"
        >
          <ChevronDown className={cn("size-4 transition-transform", isExpanded && "rotate-180")} />
        </button>
      ) : null}
    </div>
  )
}

/** Expanded panel listing the key's available models. */
function ModelsPanel({
  models,
  modelsLoading,
}: Readonly<Pick<KeyRowProps, "models" | "modelsLoading">>) {
  return (
    <div className="flex flex-col gap-2 bg-surface-inset px-13 py-3">
      <span className="font-mono text-[11px] text-text-muted">
        {modelsLoading ? "加载模型中…" : `可用模型 (${models?.length ?? 0})`}
      </span>
      {models && models.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {models.map((model) => (
            <span
              key={model}
              className="rounded-sm border border-border-subtle bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-text-secondary"
            >
              {model}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  )
}

export function KeyRow({
  maskedKey,
  revealedKey,
  apiurl,
  host,
  provider,
  balance,
  tier,
  credentialKind,
  validationState,
  scope,
  tierEvidence,
  status,
  models,
  modelsLoading,
  selected,
  onSelectedChange,
  expanded,
  onExpandedChange,
  onReveal,
  onCopy,
  onLoadModels,
  onBalance,
  onChat,
  busy,
  className,
}: Readonly<KeyRowProps>) {
  const [internalExpanded, setInternalExpanded] = useState(false)
  const isExpanded = expanded ?? internalExpanded

  const toggleExpanded = () => {
    const next = !isExpanded
    if (expanded === undefined) setInternalExpanded(next)
    onExpandedChange?.(next)
    if (next && models === undefined) onLoadModels?.()
  }

  // Only offer the models panel when a loader is wired or models already exist.
  const canExpand = Boolean(onLoadModels) || (models?.length ?? 0) > 0

  return (
    <div
      className={cn(
        "flex flex-col border-b border-border-subtle bg-surface-raised [content-visibility:auto] [contain-intrinsic-size:auto_57px]",
        className,
      )}
    >
      <div className="flex items-center gap-3.5 px-4 py-3.5">
        {onSelectedChange ? (
          <Checkbox
            checked={selected}
            onCheckedChange={(value) => onSelectedChange(value === true)}
            aria-label="Select key"
          />
        ) : null}

        <KeyCell maskedKey={maskedKey} revealedKey={revealedKey} onReveal={onReveal} onCopy={onCopy} />

        <div className="flex min-w-0 shrink-0 flex-col gap-0.5 overflow-hidden" style={colWidthStyle("endpoint")}>
          <span className="truncate font-mono text-xs text-text-secondary">{apiurl}</span>
          <span className="truncate font-mono text-[11px] text-text-muted">{host}</span>
        </div>

        <div className="flex min-w-0 shrink-0 flex-col gap-0.5 overflow-hidden" style={colWidthStyle("provider")}>
          {provider ? <ProviderBadge provider={provider} /> : null}
          {credentialKind ? (
            <span className="truncate font-mono text-[11px] text-text-muted">{credentialKind}</span>
          ) : null}
        </div>

        <div className="flex min-w-0 shrink-0 flex-col gap-0.5 overflow-hidden" style={colWidthStyle("balance")}>
          {balance ? (
            <span className="truncate font-mono text-sm font-semibold text-success">{balance}</span>
          ) : (
            <span className="font-mono text-sm text-text-muted">N/A</span>
          )}
          {tier || tierEvidence || scope ? (
            <span className="truncate font-mono text-[11px] text-text-muted" title={[scope, tier, tierEvidence].filter(Boolean).join(" · ")}>
              {/* Prefer live balance tier over scan-time tierEvidence (often "unknown"). */}
              {[scope, tier || tierEvidence].filter(Boolean).join(" · ")}
            </span>
          ) : null}
        </div>

        <div className="flex min-w-0 shrink-0 flex-col gap-0.5 overflow-hidden" style={colWidthStyle("status")}>
          {status ? <StatusBadge variant={status.variant} label={status.label} /> : null}
          {validationState ? (
            <span className="truncate font-mono text-[10px] text-text-muted">{validationState}</span>
          ) : null}
        </div>

        <RowActions
          onLoadModels={onLoadModels}
          onBalance={onBalance}
          onChat={onChat}
          busy={busy}
          canExpand={canExpand}
          isExpanded={isExpanded}
          onToggleExpand={toggleExpanded}
        />
      </div>

      {isExpanded ? <ModelsPanel models={models} modelsLoading={modelsLoading} /> : null}
    </div>
  )
}
