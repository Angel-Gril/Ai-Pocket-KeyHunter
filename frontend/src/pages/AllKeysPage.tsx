import { useCallback, useMemo, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import {
  api,
  type ChatResponse,
  type ExportFormat,
  type KeyRecord,
  type ResultKind,
} from "@/lib/api"
import { ChatTestDialog } from "@/components/chat-test-dialog"
import { KeyListToolbar, useKeyListView } from "@/components/key-list-filters"
import { BulkBar, CenterState, IndexedKeyRow, KeyPagination, KeyTableHeader } from "@/components/key-table"
import { useKeyTableSizing } from "@/components/key-table-columns"
import { extractKeyFields, formatBalance } from "@/components/key-record"
import { cn, copyToClipboard } from "@/lib/utils"

type Revealed = { apikey: string; apiurl: string }
type RowBusy = { models?: boolean; balance?: boolean; chat?: boolean }
type BalanceInfo = { balance?: string; tier?: string }

const KINDS: ResultKind[] = ["valid", "suspicious", "unavailable"]

function rowKeyOf(kind: ResultKind, index: number): string {
  return `${kind}:${index}`
}

export default function AllKeysPage() {
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<ResultKind>("valid")
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [revealed, setRevealed] = useState<Record<string, Revealed>>({})
  const [models, setModels] = useState<Record<string, string[]>>({})
  const [balances, setBalances] = useState<Record<string, BalanceInfo>>({})
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState<Record<string, RowBusy>>({})
  const [chatIndex, setChatIndex] = useState<number | null>(null)
  const [exporting, setExporting] = useState(false)
  const [chatResult, setChatResult] = useState<ChatResponse | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  const actionWidth = 360
  const { table, columnSizeVars, sizingContainerRef } = useKeyTableSizing(actionWidth)

  const validQuery = useQuery({
    queryKey: ["keys", "valid"],
    queryFn: () => api.getAllKeys("valid"),
  })
  const suspiciousQuery = useQuery({
    queryKey: ["keys", "suspicious"],
    queryFn: () => api.getAllKeys("suspicious"),
  })
  const unavailableQuery = useQuery({
    queryKey: ["keys", "unavailable"],
    queryFn: () => api.getAllKeys("unavailable"),
  })

  const activeQuery = kind === "valid" ? validQuery : kind === "suspicious" ? suspiciousQuery : unavailableQuery
  const records = useMemo<KeyRecord[]>(() => activeQuery.data?.results ?? [], [activeQuery.data])
  const validCount = validQuery.data?.results.length ?? 0
  const suspiciousCount = suspiciousQuery.data?.results.length ?? 0
  const unavailableCount = unavailableQuery.data?.results.length ?? 0

  const balanceOverrides = useMemo(() => {
    const out: Record<number, string | undefined> = {}
    for (let i = 0; i < records.length; i++) {
      const b = balances[rowKeyOf(kind, i)]?.balance
      if (b) out[i] = b
    }
    return out
  }, [records.length, balances, kind])

  const listView = useKeyListView(records, balanceOverrides)
  const { rows } = listView
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize))
  const currentPage = Math.min(page, totalPages)
  const pageRows = useMemo(
    () => rows.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [rows, currentPage, pageSize],
  )

  const stateRef = useRef({ records, kind, revealed, models, rows: pageRows })
  stateRef.current = { records, kind, revealed, models, rows: pageRows }

  const { mutateAsync: revealAsync } = useMutation({
    mutationFn: (vars: {
      kind: ResultKind
      index: number
      runId: string
      sourceIndex: number
      masked?: string
      apiurl?: string
    }) =>
      api.keyReveal({
        run_id: vars.runId,
        kind: vars.kind,
        index: vars.sourceIndex,
        // Also send masked so the server can recover if source_index is a stale seq.
        masked: vars.masked,
        apiurl: vars.apiurl,
      }),
  })
  const { mutateAsync: modelsAsync } = useMutation({ mutationFn: api.keyModels })
  const { mutateAsync: balanceAsync } = useMutation({ mutationFn: api.keyBalance })
  const { mutateAsync: chatAsync } = useMutation({ mutationFn: api.keyChat })
  const { mutate: transitionKeys, isPending: statusPending } = useMutation({
    mutationFn: ({ resultIds, status }: { resultIds: number[]; status: "valid" | "suspicious" | "unavailable" }) =>
      api.transitionKeys(resultIds, status),
    onSuccess: async (report, variables) => {
      setSelected(new Set())
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["keys", "valid"] }),
        queryClient.invalidateQueries({ queryKey: ["keys", "suspicious"] }),
        queryClient.invalidateQueries({ queryKey: ["keys", "unavailable"] }),
        queryClient.invalidateQueries({ queryKey: ["runs"] }),
        queryClient.invalidateQueries({ queryKey: ["high-value"] }),
      ])
      toast.success(
        variables.status === "valid"
          ? `已标为可用 ${report.transitioned.length} 条`
          : variables.status === "unavailable"
            ? `已标为不可用 ${report.transitioned.length} 条`
            : `已标为疑似 ${report.transitioned.length} 条`,
      )
    },
    onError: (error) => {
      toast.error("状态转换失败", { description: errorMessage(error, "状态已变化，请刷新后重试") })
    },
  })

  const transitionRow = useCallback(
    (index: number, status: "valid" | "suspicious" | "unavailable") => {
      const resultId = records[index]?.result_id
      if (typeof resultId !== "number") {
        toast.error("该记录缺少稳定 result_id")
        return
      }
      transitionKeys({ resultIds: [resultId], status })
    },
    [records, transitionKeys],
  )
  const markRowValid = useCallback((index: number) => transitionRow(index, "valid"), [transitionRow])
  const markRowSuspicious = useCallback((index: number) => transitionRow(index, "suspicious"), [transitionRow])
  const markRowUnavailable = useCallback((index: number) => transitionRow(index, "unavailable"), [transitionRow])



  const setRowBusy = useCallback((key: string, patch: RowBusy) => {
    setBusy((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }))
  }, [])

  const ensureRevealed = useCallback(
    async (index: number): Promise<Revealed> => {
      const { records: recs, kind: activeKind, revealed: cache } = stateRef.current
      const key = rowKeyOf(activeKind, index)
      const cached = cache[key]
      if (cached) return cached
      const rec = recs[index]
      if (!rec) throw new Error("record not found")
      const fields = extractKeyFields(rec)
      const runId = typeof rec.source_run_id === "string" ? rec.source_run_id : ""
      const sourceIndex = typeof rec.source_index === "number" ? rec.source_index : index
      if (!runId) throw new Error("missing source_run_id")
      const res = await revealAsync({
        kind: activeKind,
        index,
        runId,
        sourceIndex,
        masked: fields.maskedKey !== "—" ? fields.maskedKey : undefined,
        apiurl: fields.apiurl,
      })
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
      const rec = stateRef.current.records[index]
      setRowBusy(key, { balance: true })
      try {
        const { apikey, apiurl } = await ensureRevealed(index)
        const resultId = typeof rec?.result_id === "number" ? rec.result_id : undefined
        const res = await balanceAsync({
          apikey,
          apiurl,
          result_id: resultId,
        })
        const balanceLabel = formatBalance(res.balance_usd)
        const tierLabel = res.tier?.trim() || undefined
        setBalances((prev) => ({
          ...prev,
          [key]: { balance: balanceLabel, tier: tierLabel },
        }))
        // Patch react-query cache so a re-render without full refetch keeps the value.
        if (resultId != null) {
          queryClient.setQueryData<{ kind: ResultKind; results: KeyRecord[] }>(
            ["keys", stateRef.current.kind],
            (old) => {
              if (!old) return old
              return {
                ...old,
                results: old.results.map((r) =>
                  r.result_id === resultId
                    ? {
                        ...r,
                        balance: res.balance_usd || "",
                        tier: res.tier || r.tier,
                        gateway: res.gateway || r.gateway,
                        provider_evidence:
                          (res.detail as KeyRecord["provider_evidence"]) ?? r.provider_evidence,
                      }
                    : r,
                ),
              }
            },
          )
        }
        const detailParts = [
          res.gateway || "gateway",
          balanceLabel || "N/A",
          tierLabel,
          res.persisted ? "已落库" : undefined,
        ].filter(Boolean)
        toast.success("余额已更新", { description: detailParts.join(" · ") })
      } catch (err) {
        toast.error("查询余额失败", { description: errorMessage(err, "无法获取余额") })
      } finally {
        setRowBusy(key, { balance: false })
      }
    },
    [ensureRevealed, balanceAsync, setRowBusy, queryClient],
  )

  const handleExpandedChange = useCallback((index: number, isExpanded: boolean) => {
    const key = rowKeyOf(stateRef.current.kind, index)
    setExpanded((prev) => {
      const next = new Set(prev)
      if (isExpanded) next.add(key)
      else next.delete(key)
      return next
    })
  }, [])

  const handleSelectedChange = useCallback((index: number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (checked) next.add(index)
      else next.delete(index)
      return next
    })
  }, [])

  const handleToggleAll = useCallback((checked: boolean) => {
    const visible = stateRef.current.rows.map((r) => r.originalIndex)
    setSelected((prev) => {
      const next = new Set(prev)
      for (const i of visible) {
        if (checked) next.add(i)
        else next.delete(i)
      }
      return next
    })
  }, [])

  const changePage = useCallback((nextPage: number) => {
    setPage(nextPage)
    setSelected(new Set())
  }, [])

  const changePageSize = useCallback((nextPageSize: number) => {
    setPageSize(nextPageSize)
    setPage(1)
    setSelected(new Set())
  }, [])

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
    setPage(1)
  }, [])

  const runExport = useCallback(async (format: ExportFormat) => {
    setExporting(true)
    const { records: recs, kind: activeKind } = stateRef.current
    try {
      await api.export({ dataset: "all", format, kind: activeKind })
      toast.success(`已导出全部 ${recs.length} 个密钥`)
    } catch (err) {
      toast.error("导出失败", { description: errorMessage(err, "无法生成导出文件") })
    } finally {
      setExporting(false)
    }
  }, [])

  const visibleIndices = useMemo(() => pageRows.map((r) => r.originalIndex), [pageRows])
  const allChecked =
    visibleIndices.length > 0 && visibleIndices.every((i) => selected.has(i))

  const chatFields =
    chatIndex !== null && records[chatIndex] ? extractKeyFields(records[chatIndex]) : null

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
  } else if (rows.length === 0) {
    body = <CenterState>无匹配结果，试试调整搜索或筛选条件。</CenterState>
  } else {
    body = (
      <div>
        {pageRows.map(({ fields, status, originalIndex }) => {
          const key = rowKeyOf(kind, originalIndex)
          const reveal = revealed[key]
          const balanceInfo = balances[key]
          return (
            <IndexedKeyRow
              onMarkValid={kind === "suspicious" || kind === "unavailable" ? markRowValid : undefined}
              onMarkSuspicious={kind === "valid" ? markRowSuspicious : undefined}
              onMarkUnavailable={kind === "valid" ? markRowUnavailable : undefined}
              statusPending={statusPending}
              key={key}
              index={originalIndex}
              maskedKey={fields.maskedKey}
              revealedKey={reveal?.apikey}
              apiurl={reveal?.apiurl ?? fields.apiurl}
              host={fields.host}
              provider={fields.provider}
              balance={balanceInfo?.balance ?? fields.balance}
              tier={balanceInfo?.tier ?? fields.tier}
              credentialKind={fields.credentialKind}
              validationState={fields.validationState}
              scope={fields.scope}
              tierEvidence={balanceInfo ? undefined : fields.tierEvidence}
              createdAt={fields.createdAt}
              evidence={fields.evidence}
              status={status}
              models={models[key]}
              modelsLoading={busy[key]?.models}
              selected={selected.has(originalIndex)}
              expanded={expanded.has(key)}
              busy={busy[key]}
              onSelectedChange={handleSelectedChange}
              onExpandedChange={handleExpandedChange}
              onReveal={handleReveal}
              onCopy={handleCopy}
              onLoadModels={loadModels}
              onBalance={handleBalance}
              onChat={openChat}
              actionWidth={actionWidth}
            />
          )
        })}
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-col gap-3 border-b border-border-primary px-4 py-4 sm:gap-4 sm:px-6 md:px-8 md:py-[18px]">
        <div className="flex min-w-0 flex-col gap-0.5">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">全部密钥</h1>
          <p className="truncate font-mono text-xs text-text-muted">
            跨所有扫描累积 · 按 apikey 去重 · 可用 {validCount} · 疑似 {suspiciousCount} · 不可用 {unavailableCount}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {KINDS.map((tabKind) => {
            const isActive = kind === tabKind
            const count = tabKind === "valid" ? validCount : tabKind === "suspicious" ? suspiciousCount : unavailableCount
            const label = tabKind === "valid" ? "可用密钥" : tabKind === "suspicious" ? "疑似" : "不可用"
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

      <KeyListToolbar
        search={listView.search}
        onSearchChange={(value) => { listView.setSearch(value); changePage(1) }}
        provider={listView.provider}
        onProviderChange={(value) => { listView.setProvider(value); changePage(1) }}
        providers={listView.providers}
        balanceSort={listView.balanceSort}
        onBalanceSortChange={(value) => { listView.setBalanceSort(value); changePage(1) }}
        filteredCount={listView.filteredCount}
        total={listView.total}
        hasActiveFilters={listView.hasActiveFilters}
        onClear={() => { listView.clearFilters(); changePage(1) }}
      />

      <BulkBar
        selectedCount={visibleIndices.filter((index) => selected.has(index)).length}
        total={pageRows.length}
        allChecked={allChecked}
        onToggleAll={handleToggleAll}
        onExport={(format) => void runExport(format)}
        actionLabel={kind === "suspicious" ? "标为可用" : undefined}
        onAction={kind === "suspicious" ? () => {
          const resultIds = [...selected]
            .map((index) => records[index]?.result_id)
            .filter((id): id is number => typeof id === "number")
          transitionKeys({ resultIds, status: "valid" })
        } : undefined}
        actionPending={statusPending}
        exportLabel="导出全部"
        exporting={exporting}
      />

      {/* @container lets expanded KeyRow panels size to the scrollport (100cqw). */}
      <div ref={sizingContainerRef} className="@container min-h-0 flex-1 overflow-auto" style={columnSizeVars}>
        {/* Fill the viewport while preserving intrinsic width for horizontal overflow. */}
        <div className="w-max min-w-full">
          <div className="sticky top-0 z-10">
            <KeyTableHeader table={table} actionWidth={actionWidth} />
          </div>
          {body}
        </div>
      </div>
      <KeyPagination
        page={currentPage}
        pageSize={pageSize}
        totalItems={rows.length}
        onPageChange={changePage}
        onPageSizeChange={changePageSize}
      />


      <ChatTestDialog
        open={chatIndex !== null}
        onOpenChange={(open) => setChatIndex(open ? chatIndex : null)}
        maskedKey={
          chatIndex !== null
            ? revealed[rowKeyOf(kind, chatIndex)]?.apikey ?? chatFields?.maskedKey ?? ""
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
