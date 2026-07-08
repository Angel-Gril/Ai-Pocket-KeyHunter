import { useCallback, useMemo, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api, type ExportFormat, type KeyRecord } from "@/lib/api"
import { BulkBar, CenterState, IndexedKeyRow, KeyTableHeader } from "@/components/key-table"
import { deriveKeyStatus, extractKeyFields, providerOf } from "@/components/key-record"
import { cn, copyToClipboard } from "@/lib/utils"

const PROVIDER_COLORS: Record<string, string> = {
  openai: "text-accent",
  anthropic: "text-warning",
  gateway: "text-info",
}

function providerColor(provider: string): string {
  return PROVIDER_COLORS[provider] ?? "text-text-secondary"
}

export default function HighValuePage() {
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [exporting, setExporting] = useState(false)
  // Plaintext apikeys recovered via the reveal endpoint, keyed by masked value.
  const [revealed, setRevealed] = useState<Record<string, string>>({})

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["high-value"],
    queryFn: api.getHighValue,
  })

  const records = useMemo<KeyRecord[]>(() => data?.results ?? [], [data])

  const providerStats = useMemo(() => {
    const counts = new Map<string, number>()
    for (const rec of records) {
      const provider = providerOf(rec)
      counts.set(provider, (counts.get(provider) ?? 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1])
  }, [records])

  const handleSelectedChange = useCallback((index: number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (checked) next.add(index)
      else next.delete(index)
      return next
    })
  }, [])

  const handleToggleAll = useCallback(
    (checked: boolean) => setSelected(checked ? new Set(records.map((_, i) => i)) : new Set()),
    [records],
  )

  const runExport = useCallback(async (format: ExportFormat) => {
    setExporting(true)
    try {
      await api.export({ dataset: "high-value", format })
      toast.success("已导出全部高价值密钥")
    } catch (err) {
      toast.error("导出失败", {
        description: err instanceof Error ? err.message : "无法生成导出文件",
      })
    } finally {
      setExporting(false)
    }
  }, [])

  // Recover (and cache) the plaintext apikey for a row by its masked value.
  const ensureRevealed = useCallback(
    async (index: number): Promise<string> => {
      const fields = extractKeyFields(records[index])
      const cached = revealed[fields.maskedKey]
      if (cached) return cached
      const res = await api.highValueReveal({ masked: fields.maskedKey, apiurl: fields.apiurl })
      setRevealed((prev) => ({ ...prev, [fields.maskedKey]: res.apikey }))
      return res.apikey
    },
    [records, revealed],
  )

  const errorMessage = (err: unknown, fallback: string) =>
    err instanceof Error ? err.message : fallback

  const handleReveal = useCallback(
    async (index: number) => {
      try {
        await ensureRevealed(index)
      } catch (err) {
        toast.error("显示密钥失败", { description: errorMessage(err, "无法读取明文密钥") })
      }
    },
    [ensureRevealed],
  )

  const handleCopy = useCallback(
    async (index: number) => {
      try {
        const apikey = await ensureRevealed(index)
        await copyToClipboard(apikey)
        toast.success("已复制密钥到剪贴板")
      } catch (err) {
        toast.error("复制失败", { description: errorMessage(err, "剪贴板不可用") })
      }
    },
    [ensureRevealed],
  )

  const allChecked = records.length > 0 && selected.size === records.length

  // Stable per-row view model (fresh `status`/`fields` each render would defeat
  // the `IndexedKeyRow` memoization when toggling a single row's selection).
  const rows = useMemo(
    () => records.map((rec) => ({ fields: extractKeyFields(rec), status: deriveKeyStatus(rec) })),
    [records],
  )

  let body: React.ReactNode
  if (isLoading) {
    body = (
      <CenterState>
        <Loader2 className="mr-2 size-4 animate-spin" />
        加载高价值密钥中…
      </CenterState>
    )
  } else if (isError) {
    body = <CenterState className="text-danger">{error instanceof Error ? error.message : "加载失败"}</CenterState>
  } else if (records.length === 0) {
    body = <CenterState>暂无高价值密钥。</CenterState>
  } else {
    body = (
      <div className="flex-1 overflow-y-auto">
        {rows.map(({ fields, status }, index) => (
          <IndexedKeyRow
            key={`${fields.maskedKey}:${index}`}
            index={index}
            maskedKey={revealed[fields.maskedKey] ?? fields.maskedKey}
            apiurl={fields.apiurl}
            host={fields.host}
            provider={fields.provider}
            balance={fields.balance}
            tier={fields.tier}
            status={status}
            selected={selected.has(index)}
            onSelectedChange={handleSelectedChange}
            onReveal={handleReveal}
            onCopy={handleCopy}
          />
        ))}
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-col gap-4 border-b border-border-primary px-8 py-[18px]">
        <div className="flex items-center gap-4">
          <div className="flex min-w-0 flex-1 flex-col gap-0.5">
            <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">高价值 Key</h1>
            <p className="truncate font-mono text-xs text-text-muted">
              跨所有扫描累积 · 去重后 {records.length} 个 · 官方前缀 sk-proj / sk-ant
            </p>
          </div>
          {providerStats.map(([provider, count]) => (
            <div key={provider} className="flex flex-col items-end gap-0.5 px-1">
              <span className={cn("font-mono text-xl font-semibold", providerColor(provider))}>{count}</span>
              <span className="font-mono text-[11px] text-text-muted">{provider}</span>
            </div>
          ))}
        </div>
      </div>

      <BulkBar
        selectedCount={selected.size}
        total={records.length}
        allChecked={allChecked}
        onToggleAll={handleToggleAll}
        onExportJson={() => void runExport("json")}
        onExportCsv={() => void runExport("csv")}
        exporting={exporting}
        jsonLabel="导出全部 · JSON"
        csvLabel="导出全部 · CSV"
      />

      <KeyTableHeader />

      {body}
    </div>
  )
}
