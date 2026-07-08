import { useCallback, useMemo, useRef, useState } from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery } from "@tanstack/react-query"
import { ArrowLeft, Loader2 } from "lucide-react"
import { toast } from "sonner"
import {
  api,
  type ChatResponse,
  type ExportFormat,
  type KeyRecord,
  type ResultKind,
} from "@/lib/api"
import { ChatTestDialog } from "@/components/chat-test-dialog"
import { BulkBar, CenterState, IndexedKeyRow, KeyTableHeader } from "@/components/key-table"
import { deriveKeyStatus, extractKeyFields } from "@/components/key-record"
import { cn, copyToClipboard } from "@/lib/utils"

type Revealed = { apikey: string; apiurl: string }
type RowBusy = { models?: boolean; balance?: boolean; chat?: boolean }
type BalanceInfo = { balance?: string; tier?: string }

const KINDS: ResultKind[] = ["valid", "suspicious"]

function rowKeyOf(kind: ResultKind, index: number): string {
  return `${kind}:${index}`
}

function runIdToLabel(runId: string): string {
  const m = /^run_(\d{4})_(\d{2})_(\d{2})_(\d{2})-(\d{2})-(\d{2})$/.exec(runId)
  if (!m) return runId
  const [, y, mo, d, h, mi] = m
  return `${y}-${mo}-${d} ${h}:${mi}`
}

function isoToLabel(iso: string): string {
  const parsed = new Date(iso)
  if (Number.isNaN(parsed.getTime())) return ""
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`
}

export default function RunResultsPage() {
  const { runId } = useParams<{ runId: string }>()
  const [kind, setKind] = useState<ResultKind>("valid")
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [revealed, setRevealed] = useState<Record<string, Revealed>>({})
  const [models, setModels] = useState<Record<string, string[]>>({})
  const [balances, setBalances] = useState<Record<string, BalanceInfo>>({})
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState<Record<string, RowBusy>>({})
  const [exporting, setExporting] = useState(false)
  const [chatIndex, setChatIndex] = useState<number | null>(null)
  const [chatResult, setChatResult] = useState<ChatResponse | null>(null)

  const validQuery = useQuery({
    queryKey: ["run", runId, "valid"],
    queryFn: () => api.getRunResults(runId!, "valid"),
    enabled: Boolean(runId),
  })
  const suspiciousQuery = useQuery({
    queryKey: ["run", runId, "suspicious"],
    queryFn: () => api.getRunResults(runId!, "suspicious"),
    enabled: Boolean(runId),
  })
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.getRuns })

  const activeQuery = kind === "valid" ? validQuery : suspiciousQuery
  const records = useMemo<KeyRecord[]>(() => activeQuery.data?.results ?? [], [activeQuery.data])
  const validCount = validQuery.data?.results.length ?? 0
  const suspiciousCount = suspiciousQuery.data?.results.length ?? 0

  const summary = useMemo(
    () => runsQuery.data?.days.flatMap((day) => day.runs).find((run) => run.run_id === runId),
    [runsQuery.data, runId],
  )

  const subtitle = useMemo(() => {
    if (!runId) return ""
    const time = (summary?.started_at && isoToLabel(summary.started_at)) || runIdToLabel(runId)
    const parts = [time]
    if (summary?.sources.length) parts.push(summary.sources.join(","))
    if (summary && summary.hits > 0) parts.push(`命中 ${summary.hits}`)
    return parts.join(" · ")
  }, [runId, summary])

  const stateRef = useRef({ records, kind, revealed, models })
  stateRef.current = { records, kind, revealed, models }

  // Destructure the STABLE `mutateAsync` refs (the mutation objects themselves
  // change identity every render); depending on these keeps the row callbacks
  // stable so the memoized `IndexedKeyRow`s don't all re-render on any change.
  const { mutateAsync: revealAsync } = useMutation({
    mutationFn: (vars: { kind: ResultKind; index: number }) =>
      api.keyReveal({ run_id: runId!, kind: vars.kind, index: vars.index }),
  })
  const { mutateAsync: modelsAsync } = useMutation({ mutationFn: api.keyModels })
  const { mutateAsync: balanceAsync } = useMutation({ mutationFn: api.keyBalance })
  const { mutateAsync: chatAsync } = useMutation({ mutationFn: api.keyChat })

  const setRowBusy = useCallback((key: string, patch: RowBusy) => {
    setBusy((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }))
  }, [])

  const ensureRevealed = useCallback(
    async (index: number): Promise<Revealed> => {
      const { records: recs, kind: activeKind, revealed: cache } = stateRef.current
      const key = rowKeyOf(activeKind, index)
      const cached = cache[key]
      if (cached) return cached
      const fields = extractKeyFields(recs[index])
      const res = await revealAsync({ kind: activeKind, index })
      const value: Revealed = { apikey: res.apikey, apiurl: res.apiurl || fields.apiurl || "" }
      setRevealed((prev) => ({ ...prev, [key]: value }))
      return value
    },
    [revealAsync],
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
      const key = rowKeyOf(stateRef.current.kind, index)
      if (stateRef.current.records[index] === undefined) return
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
    [ensureRevealed, modelsAsync, setRowBusy],
  )

  const handleBalance = useCallback(
    async (index: number) => {
      const key = rowKeyOf(stateRef.current.kind, index)
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
    [ensureRevealed, balanceAsync, setRowBusy],
  )

  const handleExpandedChange = useCallback(
    (index: number, isExpanded: boolean) => {
      const key = rowKeyOf(stateRef.current.kind, index)
      setExpanded((prev) => {
        const next = new Set(prev)
        if (isExpanded) next.add(key)
        else next.delete(key)
        return next
      })
    },
    [],
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
    (checked: boolean) => {
      setSelected(checked ? new Set(stateRef.current.records.map((_, i) => i)) : new Set())
    },
    [],
  )

  const openChat = useCallback(
    (index: number) => {
      setChatResult(null)
      setChatIndex(index)
      const key = rowKeyOf(stateRef.current.kind, index)
      if (stateRef.current.models[key] === undefined) void loadModels(index)
    },
    [loadModels],
  )

  const handleSendChat = useCallback(
    async (model: string) => {
      if (chatIndex === null) return
      const key = rowKeyOf(stateRef.current.kind, chatIndex)
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
    [chatIndex, ensureRevealed, chatAsync, setRowBusy],
  )

  const switchKind = useCallback((next: ResultKind) => {
    setKind(next)
    setSelected(new Set())
  }, [])

  const runExport = useCallback(
    async (format: ExportFormat) => {
      if (!runId) return
      setExporting(true)
      const { records: recs, kind: activeKind } = stateRef.current
      const indices = [...selected]
      try {
        if (indices.length > 0) {
          // Export by index — the server reads the plaintext keys straight from
          // the run file, so they never round-trip through the browser.
          await api.export({ dataset: "selected", format, run_id: runId, kind: activeKind, indices })
          toast.success(`已导出 ${indices.length} 个所选密钥`)
        } else {
          await api.export({ dataset: "run", format, run_id: runId, kind: activeKind })
          toast.success(`已导出全部 ${recs.length} 个密钥`)
        }
      } catch (err) {
        toast.error("导出失败", { description: errorMessage(err, "无法生成导出文件") })
      } finally {
        setExporting(false)
      }
    },
    [runId, selected],
  )

  const allChecked = records.length > 0 && selected.size === records.length

  // Derive the stable per-row view model once per records change. Passing a
  // fresh `status` object each render would defeat the row memoization.
  const rows = useMemo(
    () => records.map((rec) => ({ fields: extractKeyFields(rec), status: deriveKeyStatus(rec) })),
    [records],
  )

  let body: React.ReactNode
  if (activeQuery.isLoading) {
    body = (
      <CenterState>
        <Loader2 className="mr-2 size-4 animate-spin" />
        加载密钥中…
      </CenterState>
    )
  } else if (activeQuery.isError) {
    body = <CenterState className="text-danger">{errorMessage(activeQuery.error, "加载失败")}</CenterState>
  } else if (records.length === 0) {
    body = <CenterState>该分类暂无密钥。</CenterState>
  } else {
    body = (
      <div className="flex-1 overflow-y-auto">
        {rows.map(({ fields, status }, index) => {
          const key = rowKeyOf(kind, index)
          const reveal = revealed[key]
          const balanceInfo = balances[key]
          return (
            <IndexedKeyRow
              key={key}
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

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-col gap-4 border-b border-border-primary px-8 py-[18px]">
        <div className="flex items-center gap-3">
          <Link
            to="/history"
            className="inline-flex items-center gap-1.5 rounded-sm border border-border-primary bg-surface-raised px-2.5 py-1.5 font-sans text-[13px] text-text-secondary transition-colors hover:text-text-primary"
          >
            <ArrowLeft className="size-3.5" />
            返回历史
          </Link>
          <div className="flex min-w-0 flex-col gap-0.5">
            <h1 className="truncate font-mono text-lg font-semibold text-text-primary">{runId}</h1>
            <p className="truncate font-mono text-xs text-text-muted">{subtitle}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {KINDS.map((tabKind) => {
            const isActive = kind === tabKind
            const count = tabKind === "valid" ? validCount : suspiciousCount
            const label = tabKind === "valid" ? "可用密钥" : "疑似"
            return (
              <button
                key={tabKind}
                type="button"
                onClick={() => switchKind(tabKind)}
                aria-pressed={isActive}
                className={cn(
                  "inline-flex items-center gap-2 rounded-sm border px-3.5 py-2 font-sans text-[13px] transition-colors",
                  isActive
                    ? "border-accent bg-accent-dim font-semibold text-accent"
                    : "border-border-primary bg-surface-raised text-text-secondary hover:text-text-primary",
                )}
              >
                {label}
                <span
                  className={cn(
                    "inline-flex min-w-5 justify-center rounded-full px-1.5 py-px font-mono text-[11px]",
                    isActive ? "bg-accent text-accent-text" : "bg-surface-overlay text-text-secondary",
                  )}
                >
                  {count}
                </span>
              </button>
            )
          })}
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
      />

      <KeyTableHeader />

      {body}

      <ChatTestDialog
        open={chatIndex !== null}
        onOpenChange={(open) => setChatIndex(open ? chatIndex : null)}
        maskedKey={
          chatIndex !== null
            ? revealed[rowKeyOf(kind, chatIndex)]?.apikey ?? rows[chatIndex]?.fields.maskedKey ?? ""
            : ""
        }
        models={chatIndex !== null ? models[rowKeyOf(kind, chatIndex)] ?? [] : []}
        modelsLoading={chatIndex !== null ? busy[rowKeyOf(kind, chatIndex)]?.models : false}
        pending={chatIndex !== null ? busy[rowKeyOf(kind, chatIndex)]?.chat : false}
        result={chatResult}
        onSend={handleSendChat}
      />
    </div>
  )
}
