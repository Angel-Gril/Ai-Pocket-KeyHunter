import { useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ChevronDown, Loader2, Plus, Save, Server, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError, type ManualTarget } from "@/lib/api"
import { ScanConsole } from "@/pages/ScanPage"
import { cn } from "@/lib/utils"

const TARGETS_PANEL_KEY = "aipocket.manual-targets.panel-open"

function formatTime(iso: string): string {
  if (!iso) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function readPanelOpen(): boolean {
  try {
    const raw = window.localStorage.getItem(TARGETS_PANEL_KEY)
    if (raw === null) return true
    return raw !== "0"
  } catch {
    return true
  }
}

/**
 * Custom hunt console — user-supplied relay/gateway URLs.
 *
 * Single collapsible panel for list + add/edit: view/delete stored
 * origins, paste new ones into the same surface, then start the global
 * scan singleton with source=manual.
 */
export default function ManualTargetsPage() {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState("")
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [panelOpen, setPanelOpen] = useState(readPanelOpen)

  const listQuery = useQuery({
    queryKey: ["manual-targets"],
    queryFn: () => api.getManualTargets({ limit: 500 }),
  })

  const targets = listQuery.data?.results ?? []
  const storedTotal = listQuery.data?.total ?? targets.length

  useEffect(() => {
    try {
      window.localStorage.setItem(TARGETS_PANEL_KEY, panelOpen ? "1" : "0")
    } catch {
      // ignore quota / private mode
    }
  }, [panelOpen])

  const saveMutation = useMutation({
    mutationFn: (replace: boolean) =>
      api.saveManualTargets({ urls: draft, replace }),
    onSuccess: (res, replace) => {
      void queryClient.invalidateQueries({ queryKey: ["manual-targets"] })
      const parts = replace
        ? [`替换为 ${res.targets.length} 条`, `新增 ${res.added}`, `更新 ${res.updated}`]
        : [`新增 ${res.added}`, `更新 ${res.updated}`]
      if (res.rejected.length > 0) {
        parts.push(`拒绝 ${res.rejected.length}`)
        toast.warning(`已保存 · ${parts.join(" · ")}`, {
          description:
            res.rejected.length <= 3
              ? `无效: ${res.rejected.join(" · ")}`
              : `无效 ${res.rejected.length} 行（已丢弃 path / 非 http(s) 等）`,
        })
      } else {
        toast.success(`已保存 · ${parts.join(" · ")}`)
      }
      // Input is for new lines only — clear after successful write.
      setDraft("")
      setSelected(new Set())
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "保存失败")
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (urls: string[]) =>
      urls.length === 1
        ? api.deleteManualTarget(urls[0])
        : api.bulkDeleteManualTargets(urls),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["manual-targets"] })
      toast.success(`已删除 ${res.deleted} 条`)
      setSelected(new Set())
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 404) {
        toast.info("地址不存在")
        void queryClient.invalidateQueries({ queryKey: ["manual-targets"] })
        return
      }
      toast.error(err instanceof Error ? err.message : "删除失败")
    },
  })

  const lineCount = useMemo(
    () =>
      draft
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean).length,
    [draft],
  )

  const toggleRow = (url: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(url)) next.delete(url)
      else next.add(url)
      return next
    })
  }

  const toggleAll = () => {
    if (selected.size === targets.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(targets.map((t) => t.url)))
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 border-b border-border-primary px-4 py-4 sm:px-6 md:px-8">
        <button
          type="button"
          aria-expanded={panelOpen}
          aria-controls="manual-targets-panel"
          onClick={() => setPanelOpen((o) => !o)}
          className="flex w-full items-start gap-3 text-left"
        >
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">
                自定义狩猎
              </h1>
              <span className="rounded-full border border-border-primary bg-surface-raised px-2 py-0.5 font-mono text-[11px] text-text-muted">
                已入库 {storedTotal}
              </span>
            </div>
            <p className="mt-[3px] font-mono text-xs text-text-muted">
              {panelOpen
                ? "统一管理中转站 / 网关地址 · 自动清洗 path · 入库后可重复扫描 · 可域名反查 FOFA / Shodan 补指纹"
                : "点击展开管理地址 · source=manual · 可域名反查 FOFA / Shodan"}
            </p>
          </div>
          <span
            className={cn(
              "mt-1 inline-flex size-8 shrink-0 items-center justify-center rounded-md border border-border-primary bg-surface-raised text-text-secondary transition-colors hover:text-text-primary",
            )}
            aria-hidden
          >
            <ChevronDown
              className={cn(
                "size-4 transition-transform duration-200",
                panelOpen && "rotate-180",
              )}
            />
          </span>
        </button>

        {panelOpen ? (
          <div id="manual-targets-panel" className="mt-4">
            <div className="overflow-hidden rounded-md border border-border-primary bg-surface-raised">
              {/* Toolbar */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle px-3 py-2">
                <span className="font-mono text-[11px] tracking-[0.3px] text-text-muted">
                  地址列表
                  <span className="ml-1.5 text-text-secondary">{storedTotal}</span>
                </span>
                {selected.size > 0 ? (
                  <button
                    type="button"
                    disabled={deleteMutation.isPending}
                    onClick={() => deleteMutation.mutate([...selected])}
                    className="inline-flex items-center gap-1.5 rounded-[4px] border border-danger bg-danger-dim px-2.5 py-1 text-[11px] font-semibold text-danger disabled:opacity-50"
                  >
                    {deleteMutation.isPending ? (
                      <Loader2 className="size-3 animate-spin" />
                    ) : (
                      <Trash2 className="size-3" />
                    )}
                    删除选中 ({selected.size})
                  </button>
                ) : (
                  <span className="font-mono text-[11px] text-text-muted">
                    勾选可批量删除 · path / query 入库时剥离
                  </span>
                )}
              </div>

              {/* Stored list */}
              <div className="max-h-[220px] overflow-auto">
                {listQuery.isLoading ? (
                  <div className="flex items-center justify-center gap-2 py-10 text-text-muted">
                    <Loader2 className="size-4 animate-spin" />
                    <span className="font-mono text-xs">加载中…</span>
                  </div>
                ) : targets.length === 0 ? (
                  <div className="flex flex-col items-center gap-2 py-8 text-text-muted">
                    <Server className="size-5 opacity-50" />
                    <span className="font-mono text-xs">暂无地址，在下方粘贴后入库</span>
                  </div>
                ) : (
                  <table className="w-full text-left text-[12px]">
                    <thead className="sticky top-0 z-10 bg-surface-raised">
                      <tr className="border-b border-border-subtle font-mono text-[11px] text-text-muted">
                        <th className="w-8 px-3 py-2">
                          <input
                            type="checkbox"
                            checked={
                              selected.size === targets.length && targets.length > 0
                            }
                            onChange={toggleAll}
                            aria-label="全选"
                          />
                        </th>
                        <th className="px-2 py-2 font-medium">URL</th>
                        <th className="w-[110px] px-2 py-2 font-medium">更新</th>
                        <th className="w-10 px-2 py-2" />
                      </tr>
                    </thead>
                    <tbody>
                      {targets.map((t: ManualTarget) => (
                        <tr
                          key={t.url}
                          className="border-b border-border-subtle last:border-0 hover:bg-surface-inset/50"
                        >
                          <td className="px-3 py-1.5">
                            <input
                              type="checkbox"
                              checked={selected.has(t.url)}
                              onChange={() => toggleRow(t.url)}
                              aria-label={`选择 ${t.url}`}
                            />
                          </td>
                          <td
                            className="max-w-[1px] truncate px-2 py-1.5 font-mono text-text-primary"
                            title={t.url}
                          >
                            {t.url}
                          </td>
                          <td className="whitespace-nowrap px-2 py-1.5 font-mono text-text-muted">
                            {formatTime(t.last_seen)}
                          </td>
                          <td className="px-2 py-1.5">
                            <button
                              type="button"
                              title="删除"
                              disabled={deleteMutation.isPending}
                              onClick={() => deleteMutation.mutate([t.url])}
                              className="rounded p-1 text-text-muted transition-colors hover:bg-danger-dim hover:text-danger"
                            >
                              <Trash2 className="size-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Add / replace — same surface */}
              <div className="border-t border-border-subtle bg-surface-inset/30 px-3 py-3">
                <label
                  htmlFor="manual-urls"
                  className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] tracking-[0.3px] text-text-muted"
                >
                  <Plus className="size-3" />
                  新增地址（每行一个）
                </label>
                <textarea
                  id="manual-urls"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder={
                    "https://web.example.com\nhttps://web1.example.com\nhttps://web2.example.com"
                  }
                  spellCheck={false}
                  rows={3}
                  className={cn(
                    "w-full resize-y rounded-md border border-border-primary bg-surface-raised",
                    "px-3 py-2 font-mono text-[13px] leading-relaxed text-text-primary",
                    "placeholder:text-text-muted focus:border-accent focus:outline-none",
                  )}
                />
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={saveMutation.isPending || lineCount === 0}
                    onClick={() => saveMutation.mutate(false)}
                    className="inline-flex items-center gap-1.5 rounded-[4px] bg-accent px-3 py-1.5 text-[12px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50"
                  >
                    {saveMutation.isPending ? (
                      <Loader2 className="size-3.5 animate-spin" />
                    ) : (
                      <Save className="size-3.5" />
                    )}
                    保存 / 追加
                  </button>
                  <button
                    type="button"
                    disabled={saveMutation.isPending || lineCount === 0}
                    onClick={() => saveMutation.mutate(true)}
                    className="inline-flex items-center gap-1.5 rounded-[4px] border border-border-primary bg-surface-raised px-3 py-1.5 text-[12px] font-medium text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50"
                    title="用上方输入完整替换已入库列表"
                  >
                    替换全部
                  </button>
                  <span className="font-mono text-[11px] text-text-muted">
                    {lineCount > 0 ? `${lineCount} 行待保存` : "粘贴后保存入库"}
                    {" · "}
                    path / query 会被剥离（如 /login/xxx）
                  </span>
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </div>

      <div className="min-h-0 flex-1">
        <ScanConsole
          fixedSource="manual"
          title="自定义狩猎"
          startLabel="开始自定义狩猎"
          subtitle="source=manual · 使用上方已入库地址 · 可域名反查 FOFA/Shodan 补指纹 · 与全量扫描共用流水线 · 结果统一入库"
        />
      </div>
    </div>
  )
}
