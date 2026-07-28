import { useCallback, useDeferredValue, useMemo, useState } from "react"
import { ArrowDownWideNarrow, ArrowUpNarrowWide, ListFilter, Search, X } from "lucide-react"
import type { KeyRecord } from "@/lib/api"
import {
  deriveKeyStatus,
  extractKeyFields,
  providerOf,
  type KeyFields,
} from "@/components/key-record"
import type { KeyRowStatus } from "@/components/key-row"
import { providerBrand } from "@/components/provider-badge"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { cn } from "@/lib/utils"

export type BalanceSort = "none" | "high-to-low" | "low-to-high"

export interface KeyListViewRow {
  originalIndex: number
  record: KeyRecord
  fields: KeyFields
  status: KeyRowStatus
  effectiveBalance?: string
}

/**
 * Approximate CNY→USD for client-side ranking only.
 * Matches the legacy backend conversion rate in balance.py (CNY / 7.2).
 * Not live FX — only used so mixed $ / ¥ lists rank sensibly.
 */
export const CNY_TO_USD_SORT_RATE = 7.2

const NON_NUMERIC_BALANCE = new Set(["n/a", "na", "—", "-", "unknown", ""])

export type ParsedBalance = {
  amount: number
  /** Detected unit; bare numbers default to USD (display path prefixes `$`). */
  currency: "USD" | "CNY"
}

/**
 * Parse a display balance string into amount + currency.
 * Supports `$12.34`, `12.34`, `¥110`, `110 CNY`, `CNY 110`, `110 元`, `N/A`, …
 */
export function parseBalance(raw?: string): ParsedBalance | null {
  if (!raw) return null
  const s = raw.trim()
  if (!s) return null
  if (NON_NUMERIC_BALANCE.has(s.toLowerCase())) return null

  const hasCny = /[¥￥]|cny|rmb|元|人民币/i.test(s)
  const hasUsd = /\$|usd|美元/i.test(s)

  // Allow thousand separators: "1,234.56"
  const match = s.replace(/,/g, "").match(/-?\d+(?:\.\d+)?/)
  if (!match) return null
  const amount = Number(match[0])
  if (!Number.isFinite(amount)) return null

  // Prefer explicit CNY markers when both appear (unusual); otherwise USD.
  if (hasCny && !hasUsd) return { amount, currency: "CNY" }
  return { amount, currency: "USD" }
}

/**
 * USD-equivalent value for multi-currency ranking.
 * CNY amounts are converted with {@link CNY_TO_USD_SORT_RATE}; unparseable → null.
 */
export function balanceSortValue(raw?: string): number | null {
  const parsed = parseBalance(raw)
  if (!parsed) return null
  if (parsed.currency === "CNY") return parsed.amount / CNY_TO_USD_SORT_RATE
  return parsed.amount
}

/** @deprecated Prefer {@link balanceSortValue}; kept as alias for call sites/tests. */
export function parseBalanceNumber(raw?: string): number | null {
  return balanceSortValue(raw)
}

function matchesSearch(row: KeyListViewRow, needle: string): boolean {
  if (!needle) return true
  const haystack = [
    row.fields.maskedKey,
    row.fields.apiurl,
    row.fields.host,
    row.fields.provider,
    row.effectiveBalance,
    row.fields.tier,
    row.fields.credentialKind,
    row.fields.validationState,
    row.fields.scope,
    row.status.label,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
  return haystack.includes(needle)
}

/**
 * Client-side search / provider filter / balance sort for key list pages.
 * Returns rows with stable `originalIndex` so reveal/export APIs keep working.
 */
export function useKeyListView(
  records: KeyRecord[],
  /** Live balance overrides keyed by original record index. */
  balanceOverrides: Readonly<Record<number, string | undefined>> = {},
) {
  const [search, setSearch] = useState("")
  const [provider, setProvider] = useState<string>("all")
  const [balanceSort, setBalanceSort] = useState<BalanceSort>("none")
  const deferredSearch = useDeferredValue(search)

  const providers = useMemo(() => {
    const counts = new Map<string, number>()
    for (const rec of records) {
      const p = providerOf(rec)
      counts.set(p, (counts.get(p) ?? 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
  }, [records])

  // Drop a stale provider filter if that provider no longer exists in the set.
  const activeProvider = provider === "all" || providers.some(([p]) => p === provider) ? provider : "all"

  const rows = useMemo(() => {
    const needle = deferredSearch.trim().toLowerCase()
    let items: KeyListViewRow[] = records.map((rec, originalIndex) => {
      const fields = extractKeyFields(rec)
      const effectiveBalance = balanceOverrides[originalIndex] ?? fields.balance
      return {
        originalIndex,
        record: rec,
        fields: { ...fields, balance: effectiveBalance },
        status: deriveKeyStatus(rec),
        effectiveBalance,
      }
    })

    if (activeProvider !== "all") {
      items = items.filter((row) => (row.fields.provider ?? "unknown") === activeProvider)
    }

    if (needle) {
      items = items.filter((row) => matchesSearch(row, needle))
    }

    if (balanceSort !== "none") {
      const dir = balanceSort === "high-to-low" ? -1 : 1
      items = [...items].sort((a, b) => {
        // Compare USD-equivalent so $ and ¥ (CNY) rank together under filters.
        const na = balanceSortValue(a.effectiveBalance)
        const nb = balanceSortValue(b.effectiveBalance)
        if (na === null && nb === null) return a.originalIndex - b.originalIndex
        if (na === null) return 1 // unknown / N/A sink to bottom
        if (nb === null) return -1
        if (na !== nb) return (na - nb) * dir
        return a.originalIndex - b.originalIndex
      })
    }

    return items
  }, [records, deferredSearch, activeProvider, balanceSort, balanceOverrides])

  const hasActiveFilters =
    search.trim().length > 0 || activeProvider !== "all" || balanceSort !== "none"

  const clearFilters = useCallback(() => {
    setSearch("")
    setProvider("all")
    setBalanceSort("none")
  }, [])

  return {
    search,
    setSearch,
    provider: activeProvider,
    setProvider,
    balanceSort,
    setBalanceSort,
    providers,
    rows,
    total: records.length,
    filteredCount: rows.length,
    hasActiveFilters,
    clearFilters,
  }
}

export interface KeyListToolbarProps {
  search: string
  onSearchChange: (value: string) => void
  provider: string
  onProviderChange: (value: string) => void
  providers: ReadonlyArray<readonly [string, number]>
  balanceSort: BalanceSort
  onBalanceSortChange: (value: BalanceSort) => void
  filteredCount: number
  total: number
  hasActiveFilters: boolean
  onClear: () => void
  className?: string
  searchPlaceholder?: string
}

export function KeyListToolbar({
  search,
  onSearchChange,
  provider,
  onProviderChange,
  providers,
  balanceSort,
  onBalanceSortChange,
  filteredCount,
  total,
  hasActiveFilters,
  onClear,
  className,
  searchPlaceholder = "搜索 key / url / host / provider…",
}: Readonly<KeyListToolbarProps>) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-2.5 border-b border-border-subtle bg-surface-base px-4 py-3 sm:px-6 md:px-8 md:py-2.5",
        className,
      )}
    >
      <div className="relative min-w-full flex-1 basis-full sm:min-w-[200px] sm:basis-[220px]">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-text-muted" />
        <Input
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder={searchPlaceholder}
          className="h-8 border-border-primary bg-surface-raised pl-8 text-[13px] dark:bg-surface-raised"
          aria-label="搜索密钥"
        />
      </div>

      <Select value={provider} onValueChange={onProviderChange}>
        <SelectTrigger
          size="sm"
          className="h-11 flex-1 border-border-primary bg-surface-raised font-sans text-[13px] text-text-secondary dark:bg-surface-raised sm:h-8 sm:min-w-[140px] sm:flex-none"
          aria-label="按 Provider 筛选"
        >
          <ListFilter className="size-3.5 text-text-muted" />
          <SelectValue placeholder="全部 Provider" />
        </SelectTrigger>
        <SelectContent align="start" position="popper">
          <SelectItem value="all">全部 Provider ({total})</SelectItem>
          {providers.map(([name, count]) => {
            const label = providerBrand(name).label || name
            return (
              <SelectItem key={name} value={name}>
                {label} ({count})
              </SelectItem>
            )
          })}
        </SelectContent>
      </Select>

      <Select
        value={balanceSort}
        onValueChange={(v) => onBalanceSortChange(v as BalanceSort)}
      >
        <SelectTrigger
          size="sm"
          className="h-11 flex-1 border-border-primary bg-surface-raised font-sans text-[13px] text-text-secondary dark:bg-surface-raised sm:h-8 sm:min-w-[150px] sm:flex-none"
          aria-label="按余额排序"
        >
          {balanceSort === "low-to-high" ? (
            <ArrowUpNarrowWide className="size-3.5 text-text-muted" />
          ) : (
            <ArrowDownWideNarrow className="size-3.5 text-text-muted" />
          )}
          <SelectValue placeholder="余额排序" />
        </SelectTrigger>
        <SelectContent align="start" position="popper">
          <SelectItem value="none">默认顺序</SelectItem>
          <SelectItem value="high-to-low">余额从高到低</SelectItem>
          <SelectItem value="low-to-high">余额从低到高</SelectItem>
        </SelectContent>
      </Select>

      <span className="ml-auto font-mono text-[11px] tabular-nums text-text-muted">
        {hasActiveFilters ? (
          <>
            显示 {filteredCount} / {total}
          </>
        ) : (
          <>共 {total}</>
        )}
      </span>

      {hasActiveFilters ? (
        <button
          type="button"
          onClick={onClear}
          className="inline-flex items-center gap-1 rounded-sm border border-border-primary bg-surface-raised px-2 py-1 font-sans text-[12px] text-text-secondary transition-colors hover:text-text-primary"
        >
          <X className="size-3" />
          清除
        </button>
      ) : null}
    </div>
  )
}
