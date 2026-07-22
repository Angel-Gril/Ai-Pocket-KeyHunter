import { useState } from "react"
import { Check, ChevronDown, Copy, Eye, EyeOff, List, Loader2, MessageSquare, Wallet } from "lucide-react"
import { Checkbox } from "@/components/ui/checkbox"
import { ProviderBadge } from "@/components/provider-badge"
import { colCellClass, colStyle, colWidthStyle } from "@/components/key-table-columns"
import { StatusBadge, type StatusVariant } from "@/components/status-badge"
import type { ProviderEvidence } from "@/lib/api"
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
  createdAt?: string
  evidence?: ProviderEvidence
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
  onPromote?: () => void
  promotePending?: boolean
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
      title={label}
      aria-label={label}
      className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-sm border border-border-primary bg-surface-overlay px-2 py-1.5 font-sans text-xs font-medium text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50 xl:px-2.5"
    >
      {loading ? <Loader2 className="size-3.5 shrink-0 animate-spin" /> : icon}
      {/* Hide labels under xl so the action cluster never crushes into vertical Chinese. */}
      <span className="hidden xl:inline">{label}</span>
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
  onPromote?: () => void
  promotePending?: boolean
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
  onPromote,
  promotePending,
  busy,
  canExpand,
  isExpanded,
  onToggleExpand,
}: Readonly<RowActionsProps>) {
  return (
    <div className="flex min-w-max flex-1 flex-nowrap items-center justify-end gap-1.5">
      {onLoadModels ? (
        <ActionButton icon={<List className="size-3.5 shrink-0" />} label="模型列表" onClick={onLoadModels} loading={busy?.models} />
      ) : null}
      {onBalance ? (
        <ActionButton icon={<Wallet className="size-3.5 shrink-0" />} label="余额" onClick={onBalance} loading={busy?.balance} />
      ) : null}
      {onPromote ? (
        <ActionButton icon={<Check className="size-3.5 shrink-0" />} label="标为可用" onClick={onPromote} loading={promotePending} />
      ) : null}
      {onChat ? (
        <ActionButton icon={<MessageSquare className="size-3.5 shrink-0" />} label="测对话" onClick={onChat} loading={busy?.chat} />
      ) : null}
      {canExpand ? (
        <button
          type="button"
          onClick={onToggleExpand}
          aria-label={isExpanded ? "Collapse models" : "Expand models"}
          aria-expanded={isExpanded}
          className="flex size-7 shrink-0 items-center justify-center rounded-sm bg-surface-overlay text-text-muted hover:text-text-primary"
        >
          <ChevronDown className={cn("size-4 transition-transform", isExpanded && "rotate-180")} />
        </button>
      ) : null}
    </div>
  )
}

/**
 * Expanded panels live under the wide `min-w-max` row track. Pin to the scrollport
 * (`sticky left-0` + `100cqw` from the key-list `@container`) so chips can wrap
 * to the visible width instead of one endless horizontal line.
 */
const EXPANDED_PANEL =
  "sticky left-0 box-border w-[100cqw] max-w-[100cqw] bg-surface-inset"

/** Expanded panel listing the key's available models. */
function ModelsPanel({
  models,
  modelsLoading,
}: Readonly<Pick<KeyRowProps, "models" | "modelsLoading">>) {
  return (
    <div className={cn(EXPANDED_PANEL, "flex flex-col gap-2 px-4 py-3 sm:px-8 xl:px-13")}>
      <span className="font-mono text-[11px] text-text-muted">
        {modelsLoading ? "加载模型中…" : `可用模型 (${models?.length ?? 0})`}
      </span>
      {models && models.length > 0 ? (
        <div className="flex flex-wrap content-start gap-1.5">
          {models.map((model) => (
            <span
              key={model}
              className="max-w-full break-all rounded-sm border border-border-subtle bg-surface-overlay px-2 py-0.5 font-mono text-[11px] text-text-secondary"
            >
              {model}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  )
}

export function formatEvidenceRecord(value: Record<string, unknown> | undefined, mask = false): string {
  if (!value || Object.keys(value).length === 0) return "N/A"
  const formatted = Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      if (mask && typeof item === "string" && item.length > 8) {
        return [key, `${item.slice(0, 4)}…${item.slice(-4)}`]
      }
      return [key, item]
    }),
  )
  return JSON.stringify(formatted)
}

function evidenceRows(evidence: ProviderEvidence): Array<[string, string]> {
  return [
    ["套餐 / 等级", evidence.plan || evidence.tier || "N/A"],
    ["账户类型", evidence.account_type || "N/A"],
    ["配额 / 剩余额度", formatEvidenceRecord(evidence.quota)],
    ["用量 / 窗口", formatEvidenceRecord(evidence.usage)],
    ["模型权限", formatEvidenceRecord(evidence.entitlements)],
    ["账户身份", formatEvidenceRecord(evidence.identity, true)],
  ]
}

export function evidenceObservedLabel(observedAt?: string): string {
  if (!observedAt) return "上次探测：N/A"
  const date = new Date(observedAt)
  return Number.isNaN(date.getTime()) ? `上次探测：${observedAt}` : `上次探测：${date.toLocaleString()}`
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
  createdAt,
  evidence,
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
  onPromote,
  promotePending,
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
  const evidenceItems = evidence ? evidenceRows(evidence) : []
  return (
    <div
      className={cn(
        "flex flex-col border-b border-border-subtle bg-surface-raised [content-visibility:auto] [contain-intrinsic-size:auto_57px]",
        className,
      )}
    >
      {/* w-full min-w-max: fill wide viewports; scroll when columns exceed the port. */}
      <div className="flex w-full min-w-max flex-nowrap items-center gap-3.5 px-4 py-3.5">
        {onSelectedChange ? (
          <Checkbox
            checked={selected}
            onCheckedChange={(value) => onSelectedChange(value === true)}
            aria-label="Select key"
          />
        ) : null}

        <KeyCell maskedKey={maskedKey} revealedKey={revealedKey} onReveal={onReveal} onCopy={onCopy} />

        <div
          className={cn("flex flex-col items-start gap-0.5 overflow-hidden", colCellClass("endpoint"))}
          style={colStyle("endpoint")}
        >
          <span className="max-w-full truncate font-mono text-xs text-text-secondary">{apiurl}</span>
          <span className="max-w-full truncate font-mono text-[11px] text-text-muted">{host}</span>
        </div>

        <div
          className={cn("flex flex-col items-start gap-0.5 overflow-hidden", colCellClass("provider"))}
          style={colStyle("provider")}
        >
          {provider ? <ProviderBadge provider={provider} /> : null}
          {credentialKind ? (
            <span className="max-w-full truncate font-mono text-[11px] text-text-muted">{credentialKind}</span>
          ) : null}
        </div>

        <div
          className={cn("flex flex-col items-start gap-0.5 overflow-hidden", colCellClass("balance"))}
          style={colStyle("balance")}
        >
          {balance ? (
            <span className="max-w-full truncate font-mono text-sm font-semibold text-success">{balance}</span>
          ) : (
            <span className="font-mono text-sm text-text-muted">N/A</span>
          )}
          {tier || tierEvidence || scope ? (
            <span className="max-w-full truncate font-mono text-[11px] text-text-muted" title={[scope, tier, tierEvidence].filter(Boolean).join(" · ")}>
              {/* Prefer live balance tier over scan-time tierEvidence (often "unknown"). */}
              {[scope, tier || tierEvidence].filter(Boolean).join(" · ")}
            </span>
          ) : null}
        </div>

        <div
          className={cn("flex flex-col items-start gap-0.5 overflow-hidden", colCellClass("createdAt"))}
          style={colStyle("createdAt")}
        >
          {createdAt ? (
            <time
              className="max-w-full truncate font-mono text-[11px] text-text-secondary"
              dateTime={createdAt}
              title={createdAt}
            >
              {new Date(createdAt).toLocaleString()}
            </time>
          ) : (
            <span className="font-mono text-[11px] text-text-muted">N/A</span>
          )}
          {evidence?.evidence_kind ? (
            <span className="max-w-full truncate font-mono text-[10px] text-text-muted">
              {evidence.evidence_kind} · {evidence.source || "provider"}
            </span>
          ) : null}
        </div>
        <div
          className={cn("flex flex-col items-start gap-0.5 overflow-hidden", colCellClass("status"))}
          style={colStyle("status")}
        >
          {status ? <StatusBadge variant={status.variant} label={status.label} /> : null}
          {validationState ? (
            <span className="max-w-full truncate font-mono text-[10px] text-text-muted">{validationState}</span>
          ) : null}
        </div>

        <RowActions
          onLoadModels={onLoadModels}
          onBalance={onBalance}
          onChat={onChat}
          onPromote={onPromote}
          promotePending={promotePending}
          busy={busy}
          canExpand={canExpand}
          isExpanded={isExpanded}
          onToggleExpand={toggleExpanded}
        />
      </div>

      {isExpanded ? <ModelsPanel models={models} modelsLoading={modelsLoading} /> : null}
      {isExpanded && evidence ? (
        <div className={cn(EXPANDED_PANEL, "border-t border-border-subtle px-4 py-3 text-xs sm:px-8")}>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3">
            {evidenceItems.map(([label, value]) => (
              <div key={label} className="min-w-0">
                <div className="font-mono text-[10px] uppercase tracking-wide text-text-muted">{label}</div>
                <div className="mt-1 break-all font-mono text-text-secondary" title={value}>{value}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap gap-3 font-mono text-[10px] text-text-muted">
            <span>{evidenceObservedLabel(evidence.observed_at)}</span>
            {evidence.detail?.cash_balance_state === "depleted" ? (
              <span className="text-warning">现金余额状态：已耗尽（无数值余额）</span>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  )
}
