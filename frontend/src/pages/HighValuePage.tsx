import { useCallback, useMemo, useRef, useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { api, type ChatResponse, type ExportFormat, type KeyRecord } from "@/lib/api"
import { ChatTestDialog } from "@/components/chat-test-dialog"
import { BulkBar, CenterState, IndexedKeyRow, KeyTableHeader } from "@/components/key-table"
import { useKeyTableSizing } from "@/components/key-table-columns"
import { deriveKeyStatus, extractKeyFields, providerOf } from "@/components/key-record"
import { providerBrand, providerBrandColor } from "@/components/provider-badge"
import { copyToClipboard } from "@/lib/utils"

type Revealed = { apikey: string; apiurl: string }
type RowBusy = { models?: boolean; balance?: boolean; chat?: boolean }
type BalanceInfo = { balance?: string; tier?: string }

export default function HighValuePage() {
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [exporting, setExporting] = useState(false)
  // Per-row state, keyed by the record's masked apikey (stable across renders).
  const [revealed, setRevealed] = useState<Record<string, Revealed>>({})
  const [models, setModels] = useState<Record<string, string[]>>({})
  const [balances, setBalances] = useState<Record<string, BalanceInfo>>({})
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState<Record<string, RowBusy>>({})
  const [chatIndex, setChatIndex] = useState<number | null>(null)
  const [chatResult, setChatResult] = useState<ChatResponse | null>(null)

  const { table, columnSizeVars } = useKeyTableSizing()

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

  // Row identity key = masked apikey. Snapshot state in a ref so the row
  // callbacks stay stable and the memoized `IndexedKeyRow`s don't all re-render.
  const stateRef = useRef({ records, revealed })
  stateRef.current = { records, revealed }

  const maskedAt = useCallback((index: number): string => {
    const rec = stateRef.current.records[index]
    return rec ? extractKeyFields(rec).maskedKey : ""
  }, [])

  const { mutateAsync: modelsAsync } = useMutation({ mutationFn: api.keyModels })
  const { mutateAsync: balanceAsync } = useMutation({ mutationFn: api.keyBalance })
  const { mutateAsync: chatAsync } = useMutation({ mutationFn: api.keyChat })

  const setRowBusy = useCallback((key: string, patch: RowBusy) => {
    setBusy((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }))
  }, [])

  // Recover (and cache) the plaintext apikey + apiurl for a row.
  const ensureRevealed = useCallback(async (index: number): Promise<Revealed> => {
    const rec = stateRef.current.records[index]
    if (!rec) throw new Error("record not found")
    const fields = extractKeyFields(rec)
    const cached = stateRef.current.revealed[fields.maskedKey]
    if (cached) return cached
    const res = await api.highValueReveal({ masked: fields.maskedKey, apiurl: fields.apiurl })
    const value: Revealed = { apikey: res.apikey, apiurl: res.apiurl || fields.apiurl || "" }
    setRevealed((prev) => ({ ...prev, [fields.maskedKey]: value }))
    return value
  }, [])

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
        const { apikey } = await ensureRevealed(index)
        await copyToClipboard(apikey)
        toast.success("已复制密钥到剪贴板")
      } catch (err) {
        toast.error("复制失败", { description: errorMessage(err, "剪贴板不可用") })
      }
    },
    [ensureRevealed],
  )

  const loadModels = useCallback(
    async (index: number) => {
      const key = maskedAt(index)
      if (!key) return
      setRowBusy(key, { models: true })
      try {
        const { apikey, apiurl } = await ensureRevealed(index)
        const res = await modelsAsync({ apikey, apiurl })
        setModels((prev) => ({ ...prev, [key]: res.models }))
        setExpanded((prev) => new Set(prev).add(key))
      } catch (err) {
        setModels((prev) => ({ ...prev, [key]: [] }))
        toast.error("加载模型失败", { description: errorMessage(err, "无法获取模型列表") })
      } finally {
        setRowBusy(key, { models: false })
      }
    },
    [ensureRevealed, modelsAsync, maskedAt, setRowBusy],
  )

  const handleBalance = useCallback(
    async (index: number) => {
      const key = maskedAt(index)
      if (!key) return
      setRowBusy(key, { balance: true })
      try {
        const { apikey, apiurl } = await ensureRevealed(index)
        const res = await balanceAsync({ apikey, apiurl })
        setBalances((prev) => ({
          ...prev,
          [key]: { balance: res.balance_usd ? `$${res.balance_usd}` : undefined, tier: res.tier || undefined },
        }))
        toast.success("余额已更新", { description: `${res.gateway || "gateway"} · ${res.balance_usd || "?"}` })
      } catch (err) {
        toast.error("查询余额失败", { description: errorMessage(err, "无法获取余额") })
      } finally {
        setRowBusy(key, { balance: false })
      }
    },
    [ensureRevealed, balanceAsync, maskedAt, setRowBusy],
  )

  const handleExpandedChange = useCallback(
    (index: number, isExpanded: boolean) => {
      const key = maskedAt(index)
      if (!key) return
      setExpanded((prev) => {
        const next = new Set(prev)
        if (isExpanded) next.add(key)
        else next.delete(key)
        return next
      })
    },
    [maskedAt],
  )

  const handleSelectedChange = useCallback((index: number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (checked) next.add(index)
      else next.delete(index)
      return next
    })
  }, [])

  const handleToggleAll = useCallback(
    (checked: boolean) =>
      setSelected(checked ? new Set(stateRef.current.records.map((_, i) => i)) : new Set()),
    [],
  )

  const openChat = useCallback(
    (index: number) => {
      setChatResult(null)
      setChatIndex(index)
      const key = maskedAt(index)
      if (key && stateRef.current.records[index] !== undefined && models[key] === undefined) {
        void loadModels(index)
      }
    },
    [loadModels, maskedAt, models],
  )

  const handleSendChat = useCallback(
    async (model: string) => {
      if (chatIndex === null) return
      const key = maskedAt(chatIndex)
      if (!key) return
      setRowBusy(key, { chat: true })
      try {
        const { apikey, apiurl } = await ensureRevealed(chatIndex)
        const res = await chatAsync({ apikey, apiurl, model })
        setChatResult(res)
        if (res.success) {
          toast.success(res.consumes_credit ? "对话成功（已消耗额度）" : "对话成功")
        } else {
          toast.error("对话失败", { description: res.error || `HTTP ${res.status_code ?? "?"}` })
        }
      } catch (err) {
        toast.error("对话请求失败", { description: errorMessage(err, "无法完成对话测试") })
      } finally {
        setRowBusy(key, { chat: false })
      }
    },
    [chatIndex, ensureRevealed, chatAsync, maskedAt, setRowBusy],
  )

  const runExport = useCallback(async (format: ExportFormat) => {
    setExporting(true)
    try {
      await api.export({ dataset: "high-value", format })
      toast.success("已导出全部高价值密钥")
    } catch (err) {
      toast.error("导出失败", { description: errorMessage(err, "无法生成导出文件") })
    } finally {
      setExporting(false)
    }
  }, [])

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
        {rows.map(({ fields, status }, index) => {
          const key = fields.maskedKey
          const reveal = revealed[key]
          const balanceInfo = balances[key]
          return (
            <IndexedKeyRow
              key={`${key}:${index}`}
              index={index}
              maskedKey={reveal?.apikey ?? fields.maskedKey}
              apiurl={reveal?.apiurl ?? fields.apiurl}
              host={fields.host}
              provider={fields.provider}
              balance={balanceInfo?.balance ?? fields.balance}
              tier={balanceInfo?.tier ?? fields.tier}
              status={status}
              models={models[key]}
              modelsLoading={busy[key]?.models}
              selected={selected.has(index)}
              expanded={expanded.has(key)}
              busy={busy[key]}
              onSelectedChange={handleSelectedChange}
              onExpandedChange={handleExpandedChange}
              onReveal={handleReveal}
              onCopy={handleCopy}
              onLoadModels={loadModels}
              onBalance={handleBalance}
              onChat={openChat}
            />
          )
        })}
      </div>
    )
  }

  const chatMasked = chatIndex !== null ? rows[chatIndex]?.fields.maskedKey ?? "" : ""

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
              <span
                className="font-mono text-xl font-semibold"
                style={{ color: providerBrandColor(provider) }}
              >
                {count}
              </span>
              <span className="font-mono text-[11px] text-text-muted">
                {providerBrand(provider).label || provider}
              </span>
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

      <div className="flex min-h-0 flex-1 flex-col" style={columnSizeVars}>
        <KeyTableHeader table={table} />
        {body}
      </div>

      <ChatTestDialog
        open={chatIndex !== null}
        onOpenChange={(open) => setChatIndex(open ? chatIndex : null)}
        maskedKey={chatIndex !== null ? revealed[chatMasked]?.apikey ?? chatMasked : ""}
        models={chatMasked ? models[chatMasked] ?? [] : []}
        modelsLoading={chatMasked ? busy[chatMasked]?.models : false}
        pending={chatMasked ? busy[chatMasked]?.chat : false}
        result={chatResult}
        onSend={handleSendChat}
      />
    </div>
  )
}
