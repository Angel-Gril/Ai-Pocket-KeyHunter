import { useEffect, useMemo, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2, Save, Server, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError, type ManualTarget } from "@/lib/api"
import { ScanConsole } from "@/pages/ScanPage"
import { cn } from "@/lib/utils"

function formatTime(iso: string): string {
  if (!iso) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/**
 * Custom hunt console — user-supplied relay/gateway URLs.
 *
 * Persist cleaned origins (scheme://host[:port], path stripped), then start the
 * same global scan singleton with source=manual — no FOFA / Shodan / GitHub.
 */
export default function ManualTargetsPage() {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState("")
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const listQuery = useQuery({
    queryKey: ["manual-targets"],
    queryFn: () => api.getManualTargets({ limit: 500 }),
  })

  const targets = listQuery.data?.results ?? []

  // Seed the textarea from stored targets once loaded (so users see prior input).
  useEffect(() => {
    if (listQuery.isSuccess && targets.length > 0 && draft === "") {
      setDraft(targets.map((t) => t.url).join("\n"))
    }
    // Only seed when the list first arrives with empty draft.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional one-shot seed
  }, [listQuery.isSuccess, listQuery.dataUpdatedAt])

  const saveMutation = useMutation({
    mutationFn: (replace: boolean) =>
      api.saveManualTargets({ urls: draft, replace }),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["manual-targets"] })
      const parts = [`新增 ${res.added}`, `更新 ${res.updated}`]
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
      // Reflect canonical URLs back into the editor.
      if (res.targets.length > 0) {
        setDraft(res.targets.map((t) => t.url).join("\n"))
      }
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
      // Drop deleted lines from draft when possible.
      if (targets.length > 0) {
        const remaining = targets
          .filter((t) => !selected.has(t.url))
          .map((t) => t.url)
        setDraft(remaining.join("\n"))
      }
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
      <div className="shrink-0 border-b border-border-primary px-8 py-5">
        <div className="mb-4 flex flex-col gap-[3px]">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">
            自定义狩猎
          </h1>
          <p className="font-mono text-xs text-text-muted">
            填入中转站 / 网关地址（每行一个）· 自动清洗 path · 入库后可重复扫描 ·
            source=manual 跳过 FOFA / Shodan / GitHub
          </p>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <div className="flex flex-col gap-2">
            <label
              htmlFor="manual-urls"
              className="font-mono text-[11px] tracking-[0.3px] text-text-muted"
            >
              地址列表（每行一个）
            </label>
            <textarea
              id="manual-urls"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={"https://web.example.com\nhttps://web1.example.com\nhttps://web2.example.com"}
              spellCheck={false}
              className={cn(
                "min-h-[140px] resize-y rounded-md border border-border-primary bg-surface-raised",
                "px-3 py-2.5 font-mono text-[13px] leading-relaxed text-text-primary",
                "placeholder:text-text-muted focus:border-accent focus:outline-none",
              )}
            />
            <div className="flex flex-wrap items-center gap-2">
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

          <div className="flex min-h-0 flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] tracking-[0.3px] text-text-muted">
                已入库（{listQuery.data?.total ?? targets.length}）
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
              ) : null}
            </div>
            <div className="max-h-[180px] overflow-y-auto rounded-md border border-border-primary bg-surface-raised">
              {listQuery.isLoading ? (
                <div className="flex items-center justify-center gap-2 py-10 text-text-muted">
                  <Loader2 className="size-4 animate-spin" />
                  <span className="font-mono text-xs">加载中…</span>
                </div>
              ) : targets.length === 0 ? (
                <div className="flex flex-col items-center gap-2 py-10 text-text-muted">
                  <Server className="size-5 opacity-50" />
                  <span className="font-mono text-xs">暂无入库地址</span>
                </div>
              ) : (
                <table className="w-full text-left text-[12px]">
                  <thead className="sticky top-0 bg-surface-raised">
                    <tr className="border-b border-border-subtle font-mono text-[11px] text-text-muted">
                      <th className="w-8 px-2 py-2">
                        <input
                          type="checkbox"
                          checked={selected.size === targets.length && targets.length > 0}
                          onChange={toggleAll}
                          aria-label="全选"
                        />
                      </th>
                      <th className="px-2 py-2 font-medium">URL</th>
                      <th className="px-2 py-2 font-medium">更新</th>
                      <th className="w-10 px-2 py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map((t: ManualTarget) => (
                      <tr
                        key={t.url}
                        className="border-b border-border-subtle last:border-0 hover:bg-surface-inset/50"
                      >
                        <td className="px-2 py-1.5">
                          <input
                            type="checkbox"
                            checked={selected.has(t.url)}
                            onChange={() => toggleRow(t.url)}
                            aria-label={`选择 ${t.url}`}
                          />
                        </td>
                        <td className="max-w-[1px] truncate px-2 py-1.5 font-mono text-text-primary">
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
          </div>
        </div>
      </div>

      <div className="min-h-0 flex-1">
        <ScanConsole
          fixedSource="manual"
          title="自定义狩猎"
          startLabel="开始自定义狩猎"
          subtitle="source=manual · 使用上方已入库地址 · 与全量扫描共用流水线 · 结果在「扫描历史 / 全部密钥 / 高价值」统一展示"
        />
      </div>
    </div>
  )
}
