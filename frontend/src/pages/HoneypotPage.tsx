import { useCallback, useDeferredValue, useEffect, useState, type FormEvent } from "react"
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Bug,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Loader2,
  Pencil,
  Plus,
  Search,
  Trash2,
} from "lucide-react"
import { toast } from "sonner"

import {
  api,
  ApiError,
  type HoneypotCreateRequest,
  type HoneypotSite,
  type HoneypotUpdateRequest,
} from "@/lib/api"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { cn } from "@/lib/utils"

function formatTime(iso: string): string {
  if (!iso) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function shortReason(reason: string): string {
  if (!reason) return "—"
  return reason.replace(/^honeypot:/, "")
}

const SOURCE_FILTERS = [
  { value: "all", label: "全部来源" },
  { value: "auto", label: "自动检测" },
  { value: "manual", label: "手动添加" },
] as const

const PAGE_SIZE_OPTIONS = [20, 50, 100] as const
const DEFAULT_PAGE_SIZE = 50

function AddDialog({
  open,
  onOpenChange,
  pending,
  onSubmit,
}: Readonly<{
  open: boolean
  onOpenChange: (open: boolean) => void
  pending: boolean
  onSubmit: (body: HoneypotCreateRequest) => void
}>) {
  const [host, setHost] = useState("")
  const [reason, setReason] = useState("honeypot:manual")
  const [notes, setNotes] = useState("")

  useEffect(() => {
    if (!open) {
      setHost("")
      setReason("honeypot:manual")
      setNotes("")
    }
  }, [open])

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    const h = host.trim()
    if (!h) {
      toast.error("请填写主机地址")
      return
    }
    onSubmit({ host: h, reason: reason.trim() || "honeypot:manual", notes: notes.trim() })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border-border-primary bg-surface-raised sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-text-primary">
            <Plus className="size-4 text-accent" />
            添加蜜罐站点
          </DialogTitle>
          <DialogDescription className="text-[13px] text-text-muted">
            加入缓存后，后续扫描会直接跳过对该站点的 probe / 验证请求。
          </DialogDescription>
        </DialogHeader>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="hp-host" className="text-[13px] text-text-secondary">
              主机地址
            </Label>
            <Input
              id="hp-host"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="https://1.2.3.4:8080 或 host:port"
              className="border-border-primary bg-surface-overlay font-mono text-[13px]"
              autoFocus
              disabled={pending}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="hp-reason" className="text-[13px] text-text-secondary">
              原因标签
            </Label>
            <Input
              id="hp-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="honeypot:manual"
              className="border-border-primary bg-surface-overlay font-mono text-[13px]"
              disabled={pending}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="hp-notes" className="text-[13px] text-text-secondary">
              备注
            </Label>
            <textarea
              id="hp-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              placeholder="可选"
              disabled={pending}
              className="min-h-[56px] w-full resize-y rounded-md border border-border-primary bg-surface-overlay px-3 py-2 font-mono text-[13px] text-text-primary outline-none placeholder:text-text-muted focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:opacity-50"
            />
          </div>
          <DialogFooter className="gap-2 sm:justify-end">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={pending}
              className="inline-flex items-center justify-center rounded-[4px] border border-border-primary bg-surface-raised px-4 py-[9px] text-[13px] font-semibold text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={pending}
              className="inline-flex items-center justify-center gap-2 rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {pending ? <Loader2 className="size-[15px] animate-spin" /> : <Plus className="size-[15px]" />}
              添加
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function EditDialog({
  site,
  open,
  onOpenChange,
  pending,
  onSubmit,
}: Readonly<{
  site: HoneypotSite | null
  open: boolean
  onOpenChange: (open: boolean) => void
  pending: boolean
  onSubmit: (body: HoneypotUpdateRequest) => void
}>) {
  const [reason, setReason] = useState("")
  const [notes, setNotes] = useState("")

  useEffect(() => {
    if (site && open) {
      setReason(site.reason)
      setNotes(site.notes)
    }
  }, [site, open])

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (!site) return
    onSubmit({ host_key: site.host_key, reason: reason.trim(), notes })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border-border-primary bg-surface-raised sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-text-primary">
            <Pencil className="size-4 text-accent" />
            编辑蜜罐站点
          </DialogTitle>
          <DialogDescription className="truncate font-mono text-[12px] text-text-muted">
            {site?.host_key}
          </DialogDescription>
        </DialogHeader>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-1.5">
            <Label className="text-[13px] text-text-secondary">原因标签</Label>
            <Input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="border-border-primary bg-surface-overlay font-mono text-[13px]"
              disabled={pending}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label className="text-[13px] text-text-secondary">备注</Label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              disabled={pending}
              className="min-h-[56px] w-full resize-y rounded-md border border-border-primary bg-surface-overlay px-3 py-2 font-mono text-[13px] text-text-primary outline-none placeholder:text-text-muted focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:opacity-50"
            />
          </div>
          <DialogFooter className="gap-2 sm:justify-end">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={pending}
              className="inline-flex items-center justify-center rounded-[4px] border border-border-primary bg-surface-raised px-4 py-[9px] text-[13px] font-semibold text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={pending}
              className="inline-flex items-center justify-center gap-2 rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {pending ? <Loader2 className="size-[15px] animate-spin" /> : null}
              保存
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function HoneypotPage() {
  const queryClient = useQueryClient()
  const [query, setQuery] = useState("")
  const deferredQuery = useDeferredValue(query.trim())
  const [sourceFilter, setSourceFilter] = useState<string>("all")
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [addOpen, setAddOpen] = useState(false)
  const [editSite, setEditSite] = useState<HoneypotSite | null>(null)

  const listQuery = useQuery({
    queryKey: ["honeypot", sourceFilter, deferredQuery, page, pageSize],
    queryFn: () =>
      api.getHoneypots({
        q: deferredQuery,
        source: sourceFilter === "all" ? "" : sourceFilter,
        limit: pageSize,
        offset: (page - 1) * pageSize,
      }),
    placeholderData: keepPreviousData,
  })

  const sites = listQuery.data?.results ?? []
  const total = listQuery.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const currentPage = Math.min(page, totalPages)

  useEffect(() => {
    if (listQuery.data && page > totalPages) setPage(totalPages)
  }, [listQuery.data, page, totalPages])

  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ["honeypot"] })
  }, [queryClient])

  const createMutation = useMutation({
    mutationFn: api.createHoneypot,
    onSuccess: (row) => {
      toast.success(`已加入蜜罐缓存 · ${row.host_key}`)
      setAddOpen(false)
      invalidate()
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "添加失败")
    },
  })

  const updateMutation = useMutation({
    mutationFn: api.updateHoneypot,
    onSuccess: () => {
      toast.success("已更新")
      setEditSite(null)
      invalidate()
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "更新失败")
    },
  })

  const deleteMutation = useMutation({
    mutationFn: api.deleteHoneypot,
    onSuccess: () => {
      toast.success("已删除 · 后续扫描将重新探测该站点")
      invalidate()
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "删除失败")
    },
  })

  const bulkDeleteMutation = useMutation({
    mutationFn: api.bulkDeleteHoneypots,
    onSuccess: (res) => {
      toast.success(`已删除 ${res.deleted} 条`)
      setSelected(new Set())
      invalidate()
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "批量删除失败")
    },
  })

  const allPageSelected =
    sites.length > 0 && sites.every((site) => selected.has(site.host_key))

  const toggleAll = () => {
    setSelected((previous) => {
      const next = new Set(previous)
      for (const site of sites) {
        if (allPageSelected) next.delete(site.host_key)
        else next.add(site.host_key)
      }
      return next
    })
  }

  const toggleOne = (key: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const handleDeleteOne = (site: HoneypotSite) => {
    const members = site.member_count ?? 1
    if (!window.confirm(`确认从蜜罐缓存删除该组的 ${members} 个站点？\n${site.host}\n删除后下次扫描会重新请求该域名组。`)) {
      return
    }
    deleteMutation.mutate(site.host_key)
  }

  const handleBulkDelete = () => {
    const keys = [...selected]
    if (keys.length === 0) return
    if (!window.confirm(`确认删除选中的 ${keys.length} 个蜜罐站点？`)) return
    bulkDeleteMutation.mutate(keys)
  }

  const pageStart = total === 0 ? 0 : (currentPage - 1) * pageSize + 1
  const pageEnd = Math.min(currentPage * pageSize, total)
  const countLabel = total === 0 ? "共 0 条" : `显示 ${pageStart}–${pageEnd} / 共 ${total} 条`
  const hasFilters = deferredQuery.length > 0 || sourceFilter !== "all"

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-col gap-3 border-b border-border-primary px-4 py-4 sm:flex-row sm:flex-wrap sm:items-center sm:gap-3 sm:px-6 md:px-8 md:py-5">
        <div className="flex min-w-0 flex-1 flex-col gap-[3px]">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">蜜罐站点</h1>
          <p className="font-mono text-xs text-text-muted">
            honeypot_sites · {countLabel} · 扫描前跳过已知蜜罐，判定后增量写入
          </p>
        </div>

        <div className="relative flex w-full items-center sm:w-auto">
          <Search className="pointer-events-none absolute left-3 size-[15px] text-text-muted" />
          <Input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelected(new Set())
              setPage(1)
            }}
            placeholder="搜索 host / reason / notes…"
            className="w-full border-border-primary bg-surface-raised pl-9 text-[13px] dark:bg-surface-raised sm:w-[240px]"
            aria-label="搜索蜜罐站点"
          />
        </div>

        <Select
          value={sourceFilter}
          onValueChange={(value) => {
            setSourceFilter(value)
            setSelected(new Set())
            setPage(1)
          }}
        >
          <SelectTrigger className="min-h-11 w-full border-border-primary bg-surface-raised font-mono text-[12px] sm:min-h-0 sm:w-[140px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SOURCE_FILTERS.map((f) => (
              <SelectItem key={f.value} value={f.value} className="font-mono text-xs">
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {selected.size > 0 ? (
          <button
            type="button"
            onClick={handleBulkDelete}
            disabled={bulkDeleteMutation.isPending}
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-[4px] border border-danger/40 bg-danger-dim px-4 py-[9px] text-[13px] font-semibold text-danger transition-opacity hover:opacity-90 disabled:opacity-50 sm:min-h-0"
          >
            {bulkDeleteMutation.isPending ? (
              <Loader2 className="size-[15px] animate-spin" />
            ) : (
              <Trash2 className="size-[15px]" />
            )}
            删除选中 ({selected.size})
          </button>
        ) : null}

        <button
          type="button"
          onClick={() => setAddOpen(true)}
          className="inline-flex min-h-11 items-center justify-center gap-2 rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 sm:min-h-0"
        >
          <Plus className="size-[15px]" />
          手动添加
        </button>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-6 md:px-8 md:py-6">
        {listQuery.isPending ? (
          <div className="flex h-full items-center justify-center gap-2 font-mono text-sm text-text-muted">
            <Loader2 className="size-4 animate-spin" />
            加载中…
          </div>
        ) : listQuery.isError ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-text-muted">
            <Bug className="size-6 text-danger" />
            <span className="font-mono text-sm">加载蜜罐列表失败（需配置 PostgreSQL）</span>
          </div>
        ) : total === 0 && !hasFilters ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-text-muted">
            <Bug className="size-6 text-text-muted" />
            <span className="font-mono text-sm">暂无蜜罐站点 · 跑一次全量扫描后会自动累积</span>
            <span className="max-w-md text-center font-mono text-[11px] text-text-muted">
              判定为 no-auth / steganography / response-cluster 等站点会写入此表；
              下次扫描 discovery 后直接跳过请求。
            </span>
          </div>
        ) : total === 0 || sites.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 text-text-muted">
            <Bug className="size-6 text-text-muted" />
            <span className="font-mono text-sm">无匹配结果</span>
          </div>
        ) : (
          <div className="rounded-md border border-border-primary bg-surface-raised">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-10">
                    <input
                      type="checkbox"
                      checked={allPageSelected}
                      onChange={toggleAll}
                      aria-label="全选"
                      className="size-3.5 accent-[var(--color-accent)]"
                    />
                  </TableHead>
                  <TableHead className="font-mono text-[11px] text-text-muted">主机</TableHead>
                  <TableHead className="w-[140px] font-mono text-[11px] text-text-muted">原因</TableHead>
                  <TableHead className="w-[80px] font-mono text-[11px] text-text-muted">来源</TableHead>
                  <TableHead className="w-[70px] font-mono text-[11px] text-text-muted">命中</TableHead>
                  <TableHead className="w-[140px] font-mono text-[11px] text-text-muted">最近确认</TableHead>
                  <TableHead className="font-mono text-[11px] text-text-muted">备注</TableHead>
                  <TableHead className="w-[90px] font-mono text-[11px] text-text-muted">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sites.map((site) => (
                  <TableRow key={site.host_key}>
                    <TableCell>
                      <input
                        type="checkbox"
                        checked={selected.has(site.host_key)}
                        onChange={() => toggleOne(site.host_key)}
                        aria-label={`选择 ${site.host_key}`}
                        className="size-3.5 accent-[var(--color-accent)]"
                      />
                    </TableCell>
                    <TableCell className="max-w-[280px]">
                      <span className="block truncate font-mono text-[12px] text-text-primary" title={site.host_key}>
                        {site.host || site.host_key}
                      </span>
                      {(site.member_count ?? 1) > 1 ? (
                        <span className="font-mono text-[10px] text-text-muted">
                          已合并 {site.member_count} 个子域名 / 端口
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <span
                        className="inline-flex max-w-[130px] truncate rounded-[4px] bg-danger-dim px-2 py-0.5 font-mono text-[11px] font-semibold text-danger"
                        title={site.reason}
                      >
                        {shortReason(site.reason)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span
                        className={cn(
                          "inline-flex rounded-[4px] px-2 py-0.5 font-mono text-[11px] font-semibold",
                          site.source === "manual"
                            ? "bg-accent/15 text-accent"
                            : "bg-surface-overlay text-text-secondary",
                        )}
                      >
                        {site.source === "manual" ? "手动" : "自动"}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-[12px] text-text-secondary">
                      {site.hit_count}
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-text-muted">
                      {formatTime(site.last_seen)}
                    </TableCell>
                    <TableCell className="max-w-[160px]">
                      <span className="block truncate text-[12px] text-text-secondary" title={site.notes}>
                        {site.notes || "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          onClick={() => setEditSite(site)}
                          className="rounded p-1.5 text-text-muted transition-colors hover:bg-surface-overlay hover:text-text-primary"
                          aria-label="编辑"
                        >
                          <Pencil className="size-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteOne(site)}
                          disabled={deleteMutation.isPending}
                          className="rounded p-1.5 text-text-muted transition-colors hover:bg-danger-dim hover:text-danger"
                          aria-label="删除"
                        >
                          <Trash2 className="size-3.5" />
                        </button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="flex flex-col gap-3 border-t border-border-primary px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2 font-mono text-[11px] text-text-muted">
                <span>第 {currentPage} / {totalPages} 页</span>
                <Select
                  value={String(pageSize)}
                  onValueChange={(value) => {
                    setPageSize(Number(value))
                    setSelected(new Set())
                    setPage(1)
                  }}
                >
                  <SelectTrigger className="h-8 w-[92px] border-border-primary bg-surface-overlay font-mono text-[11px]" aria-label="每页条数">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAGE_SIZE_OPTIONS.map((size) => (
                      <SelectItem key={size} value={String(size)} className="font-mono text-xs">
                        {size} 条/页
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <nav className="flex items-center gap-1" aria-label="蜜罐列表分页">
                <button
                  type="button"
                  onClick={() => setPage(1)}
                  disabled={currentPage === 1 || listQuery.isFetching}
                  className="inline-flex size-8 items-center justify-center rounded-[4px] border border-border-primary text-text-muted transition-colors hover:bg-surface-overlay hover:text-text-primary disabled:pointer-events-none disabled:opacity-40"
                  aria-label="第一页"
                >
                  <ChevronsLeft className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                  disabled={currentPage === 1 || listQuery.isFetching}
                  className="inline-flex size-8 items-center justify-center rounded-[4px] border border-border-primary text-text-muted transition-colors hover:bg-surface-overlay hover:text-text-primary disabled:pointer-events-none disabled:opacity-40"
                  aria-label="上一页"
                >
                  <ChevronLeft className="size-3.5" />
                </button>
                <span className="min-w-16 px-2 text-center font-mono text-[11px] text-text-secondary">
                  {pageStart}–{pageEnd}
                </span>
                <button
                  type="button"
                  onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                  disabled={currentPage === totalPages || listQuery.isFetching}
                  className="inline-flex size-8 items-center justify-center rounded-[4px] border border-border-primary text-text-muted transition-colors hover:bg-surface-overlay hover:text-text-primary disabled:pointer-events-none disabled:opacity-40"
                  aria-label="下一页"
                >
                  <ChevronRight className="size-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => setPage(totalPages)}
                  disabled={currentPage === totalPages || listQuery.isFetching}
                  className="inline-flex size-8 items-center justify-center rounded-[4px] border border-border-primary text-text-muted transition-colors hover:bg-surface-overlay hover:text-text-primary disabled:pointer-events-none disabled:opacity-40"
                  aria-label="最后一页"
                >
                  <ChevronsRight className="size-3.5" />
                </button>
              </nav>
            </div>
          </div>
        )}
      </div>

      <AddDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        pending={createMutation.isPending}
        onSubmit={(body) => createMutation.mutate(body)}
      />
      <EditDialog
        site={editSite}
        open={editSite != null}
        onOpenChange={(open) => {
          if (!open) setEditSite(null)
        }}
        pending={updateMutation.isPending}
        onSubmit={(body) => updateMutation.mutate(body)}
      />
    </div>
  )
}
