import { useCallback, useDeferredValue, useEffect, useMemo, useState, type FormEvent } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Braces,
  Link2,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react"
import { toast } from "sonner"

import { api, ApiError, type CveAddRequest, type CveRecord } from "@/lib/api"
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
import { cn } from "@/lib/utils"

function downloadJson(data: unknown, filename: string): void {
  const blob = new Blob([`${JSON.stringify(data, null, 2)}\n`], {
    type: "application/json;charset=utf-8",
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

interface NormalCve {
  id: string
  title: string
  type: string
  description: string
  sourceUrl: string
  severity: "high" | "medium" | "low"
  manual: boolean
}

const CVE_TYPES = [
  "API key泄露",
  "认证绕过",
  "SSRF",
  "信息泄露",
  "SQL注入",
  "RCE",
  "权限提升",
] as const

const SEVERITY_META: Record<NormalCve["severity"], { label: string; badge: string }> = {
  high: { label: "高危", badge: "bg-danger-dim text-danger" },
  medium: { label: "中危", badge: "bg-warning-dim text-warning" },
  low: { label: "低危", badge: "bg-info-dim text-info" },
}

function str(value: unknown): string {
  if (typeof value === "string") return value
  if (typeof value === "number" || typeof value === "boolean") return String(value)
  return ""
}

function normalize(record: CveRecord): NormalCve {
  const id = str(record.id ?? record.cve_id ?? record.cve) || "UNKNOWN"
  const product = str(record.product)
  const type = str(record.type ?? record.category)
  const description = str(record.description ?? record.summary ?? record.content)
  const sourceUrl = str(record.source_url ?? record.url ?? record.link)

  const huntable = str(record.huntable)
  const cvss = typeof record.cvss === "number" ? record.cvss : Number(record.cvss) || 0
  let severity: NormalCve["severity"] = "low"
  if (huntable.includes("高") || cvss >= 8) severity = "high"
  else if (huntable.includes("中") || cvss >= 4) severity = "medium"

  let title = type || id
  if (product) title = type ? `${product} · ${type}` : product

  return {
    id,
    title,
    type,
    description,
    sourceUrl,
    severity,
    manual: record.manual === true,
  }
}

function CveCard({ cve }: Readonly<{ cve: NormalCve }>) {
  const meta = SEVERITY_META[cve.severity]
  return (
    <article className="flex flex-col gap-2.5 rounded-md border border-border-primary bg-surface-raised p-[18px] [content-visibility:auto] [contain-intrinsic-size:auto_150px]">
      <div className="flex items-center gap-3">
        <span className="font-mono text-sm font-semibold text-accent">{cve.id}</span>
        <span
          className={cn(
            "inline-flex items-center gap-[5px] rounded-[4px] px-[9px] py-[3px] font-mono text-[11px] font-semibold",
            meta.badge,
          )}
        >
          <TriangleAlert className="size-3" />
          {meta.label}
        </span>
        {cve.manual ? (
          <span className="inline-flex items-center rounded-[4px] bg-accent/15 px-[9px] py-[3px] font-mono text-[11px] font-semibold text-accent">
            手动
          </span>
        ) : null}
        <h2 className="min-w-0 flex-1 truncate text-[15px] font-semibold text-text-primary">
          {cve.title}
        </h2>
      </div>
      {cve.description ? (
        <p className="text-[13px] leading-normal text-text-secondary">{cve.description}</p>
      ) : null}
      {cve.sourceUrl ? (
        <a
          href={cve.sourceUrl}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex w-fit items-center gap-1.5 font-mono text-xs text-info hover:underline"
        >
          <Link2 className="size-[13px] text-text-muted" />
          <span className="truncate">{cve.sourceUrl}</span>
        </a>
      ) : null}
    </article>
  )
}

function matchesCve(cve: NormalCve, needle: string): boolean {
  if (!needle) return true
  const haystack = [
    cve.id,
    cve.title,
    cve.type,
    cve.description,
    cve.sourceUrl,
    SEVERITY_META[cve.severity].label,
    cve.manual ? "手动" : "",
  ]
    .join(" ")
    .toLowerCase()
  return haystack.includes(needle)
}

const EMPTY_FORM = {
  url: "",
  id: "",
  product: "",
  type: "",
  description: "",
  cvss: "",
}

function AddCveDialog({
  open,
  onOpenChange,
  pending,
  onSubmit,
}: Readonly<{
  open: boolean
  onOpenChange: (open: boolean) => void
  pending: boolean
  onSubmit: (body: CveAddRequest) => void
}>) {
  const [form, setForm] = useState(EMPTY_FORM)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const reset = useCallback(() => {
    setForm(EMPTY_FORM)
    setShowAdvanced(false)
  }, [])

  // Reset when closed from parent (e.g. after successful add) or via dialog dismiss.
  useEffect(() => {
    if (!open) reset()
  }, [open, reset])

  const handleOpenChange = useCallback(
    (next: boolean) => {
      onOpenChange(next)
    },
    [onOpenChange],
  )

  const handleSubmit = useCallback(
    (event: FormEvent) => {
      event.preventDefault()
      const url = form.url.trim()
      const id = form.id.trim()
      if (!url && !id) {
        toast.error("请至少填写来源 URL 或 CVE ID")
        return
      }
      const body: CveAddRequest = {}
      if (url) body.url = url
      if (id) body.id = id
      if (form.product.trim()) body.product = form.product.trim()
      if (form.type) body.type = form.type
      if (form.description.trim()) body.description = form.description.trim()
      const cvss = Number(form.cvss)
      if (form.cvss.trim() && !Number.isNaN(cvss)) body.cvss = cvss
      onSubmit(body)
    },
    [form, onSubmit],
  )

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[min(90dvh,720px)] overflow-y-auto border-border-primary bg-surface-raised sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 pr-6 text-text-primary">
            <Plus className="size-4 shrink-0 text-accent" />
            手动添加 CVE
          </DialogTitle>
          <DialogDescription className="text-[13px] text-text-muted">
            粘贴 advisory / NVD / GitHub 链接自动解析，或直接填写字段。添加后会写入 CVE
            库，同步时不会被清掉。
          </DialogDescription>
        </DialogHeader>

        <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-2">
            <Label htmlFor="cve-url" className="text-[13px] text-text-secondary">
              来源 URL
            </Label>
            <Input
              id="cve-url"
              value={form.url}
              onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
              placeholder="https://nvd.nist.gov/vuln/detail/CVE-…"
              className="border-border-primary bg-surface-overlay font-mono text-[13px] text-text-primary dark:bg-surface-overlay"
              autoFocus
              disabled={pending}
            />
            <p className="font-mono text-[11px] text-text-muted">
              支持 NVD、GitHub Advisory、Huntr 等页面；会抓取并解析 ID / 产品 / 类型
            </p>
          </div>

          <button
            type="button"
            onClick={() => setShowAdvanced((v) => !v)}
            className="self-start font-mono text-xs text-text-muted transition-colors hover:text-text-secondary"
          >
            {showAdvanced ? "收起手动字段 ▴" : "手动填写 / 覆盖字段 ▾"}
          </button>

          {showAdvanced ? (
            <div className="flex flex-col gap-3 rounded-md border border-border-primary bg-surface-inset/40 p-3.5">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="cve-id" className="text-[12px] text-text-secondary">
                    CVE / GHSA ID
                  </Label>
                  <Input
                    id="cve-id"
                    value={form.id}
                    onChange={(e) => setForm((f) => ({ ...f, id: e.target.value }))}
                    placeholder="CVE-2026-…"
                    className="border-border-primary bg-surface-overlay font-mono text-[13px] dark:bg-surface-overlay"
                    disabled={pending}
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="cve-product" className="text-[12px] text-text-secondary">
                    产品
                  </Label>
                  <Input
                    id="cve-product"
                    value={form.product}
                    onChange={(e) => setForm((f) => ({ ...f, product: e.target.value }))}
                    placeholder="litellm / dify / openwebui…"
                    className="border-border-primary bg-surface-overlay font-mono text-[13px] dark:bg-surface-overlay"
                    disabled={pending}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[12px] text-text-secondary">类型</Label>
                  <Select
                    value={form.type || undefined}
                    onValueChange={(value) => setForm((f) => ({ ...f, type: value }))}
                    disabled={pending}
                  >
                    <SelectTrigger className="w-full border-border-primary bg-surface-overlay font-mono text-[13px] text-text-primary">
                      <SelectValue placeholder="选择类型（可选）" />
                    </SelectTrigger>
                    <SelectContent>
                      {CVE_TYPES.map((t) => (
                        <SelectItem key={t} value={t} className="font-mono text-xs">
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="cve-cvss" className="text-[12px] text-text-secondary">
                    CVSS
                  </Label>
                  <Input
                    id="cve-cvss"
                    type="number"
                    min={0}
                    max={10}
                    step={0.1}
                    value={form.cvss}
                    onChange={(e) => setForm((f) => ({ ...f, cvss: e.target.value }))}
                    placeholder="0.0 – 10.0"
                    className="border-border-primary bg-surface-overlay font-mono text-[13px] dark:bg-surface-overlay"
                    disabled={pending}
                  />
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="cve-desc" className="text-[12px] text-text-secondary">
                  描述
                </Label>
                <textarea
                  id="cve-desc"
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  placeholder="简要描述漏洞与影响…"
                  rows={3}
                  disabled={pending}
                  className="min-h-[72px] w-full resize-y rounded-md border border-border-primary bg-surface-overlay px-3 py-2 font-mono text-[13px] text-text-primary outline-none placeholder:text-text-muted focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:opacity-50"
                />
              </div>
            </div>
          ) : null}

          <DialogFooter className="gap-2 sm:justify-end">
            <button
              type="button"
              onClick={() => handleOpenChange(false)}
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
              解析并添加
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function CvePage() {
  const queryClient = useQueryClient()
  const [query, setQuery] = useState("")
  const [addOpen, setAddOpen] = useState(false)
  const deferredQuery = useDeferredValue(query)

  const cveQuery = useQuery({
    queryKey: ["cve"],
    queryFn: api.getCve,
  })

  const indexedCves = useMemo(
    () => (cveQuery.data?.cves ?? []).map((raw) => ({ raw, normalized: normalize(raw) })),
    [cveQuery.data],
  )

  const needle = deferredQuery.trim().toLowerCase()
  const filteredCves = useMemo(
    () => (needle ? indexedCves.filter(({ normalized }) => matchesCve(normalized, needle)) : indexedCves),
    [indexedCves, needle],
  )
  const cves = useMemo(() => indexedCves.map(({ normalized }) => normalized), [indexedCves])
  const filtered = useMemo(() => filteredCves.map(({ normalized }) => normalized), [filteredCves])
  const filteredRaw = useMemo(() => filteredCves.map(({ raw }) => raw), [filteredCves])

  const syncMutation = useMutation({
    mutationFn: api.cveSync,
    onSuccess: (res) => {
      toast.success(`同步完成 · 新增 ${res.added} 条 · 共 ${res.total} 条`)
      void queryClient.invalidateQueries({ queryKey: ["cve"] })
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "同步 CVE 失败")
    },
  })

  const addMutation = useMutation({
    mutationFn: api.cveAdd,
    onSuccess: (res) => {
      const id = str(res.cve.id)
      if (res.created) {
        toast.success(`已添加 ${id} · 库内共 ${res.total} 条`)
      } else {
        // Same id already stored — skip write entirely (no DB / file update).
        toast.message(`「${id}」已存在`, {
          description: `未写入数据库，库内仍为 ${res.total} 条`,
        })
      }
      setAddOpen(false)
      void queryClient.invalidateQueries({ queryKey: ["cve"] })
    },
    onError: (err) => {
      toast.error(err instanceof ApiError ? err.message : "添加 CVE 失败")
    },
  })

  const handleExportJson = useCallback(() => {
    if (filteredRaw.length === 0) {
      toast.error("没有可导出的 CVE 记录")
      return
    }
    const stamp = new Date().toISOString().slice(0, 10)
    const filename =
      needle.length > 0
        ? `aipocket-cve-filtered-${stamp}.json`
        : `aipocket-cve-${stamp}.json`
    try {
      downloadJson(filteredRaw, filename)
      toast.success(`已导出 ${filteredRaw.length} 条 CVE · JSON`)
    } catch {
      toast.error("导出失败")
    }
  }, [filteredRaw, needle])

  const countLabel =
    needle.length > 0
      ? `显示 ${filtered.length} / ${cves.length} 条`
      : `${cves.length} 条`

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-col gap-3 border-b border-border-primary px-4 py-4 sm:flex-row sm:flex-wrap sm:items-center sm:gap-4 sm:px-6 md:px-8 md:py-5">
        <div className="flex flex-1 flex-col gap-[3px]">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">CVE 库</h1>
          <p className="font-mono text-xs text-text-muted">
            sources/cve_2026_ai.json · {countLabel} · 面向 AI 网关的凭据泄露漏洞
          </p>
        </div>

        <div className="relative flex w-full items-center sm:w-auto">
          <Search className="pointer-events-none absolute left-3 size-[15px] text-text-muted" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索 CVE / 产品 / 描述…"
            className="w-full border-border-primary bg-surface-raised pl-9 text-[13px] dark:bg-surface-raised sm:w-[260px]"
            aria-label="搜索 CVE"
          />
        </div>

        <button
          type="button"
          onClick={() => setAddOpen(true)}
          className="inline-flex min-h-11 flex-1 items-center justify-center gap-2 rounded-[4px] border border-border-primary bg-surface-raised px-4 py-[9px] text-[13px] font-semibold text-text-secondary transition-colors hover:text-text-primary sm:min-h-0 sm:flex-none"
        >
          <Plus className="size-[15px]" />
          手动添加
        </button>

        <button
          type="button"
          onClick={handleExportJson}
          disabled={filteredRaw.length === 0 || cveQuery.isPending}
          className="inline-flex min-h-11 flex-1 items-center justify-center gap-2 rounded-[4px] border border-border-primary bg-surface-raised px-4 py-[9px] text-[13px] font-semibold text-text-secondary transition-colors hover:text-text-primary disabled:opacity-50 sm:min-h-0 sm:flex-none"
        >
          <Braces className="size-[15px]" />
          导出 JSON
        </button>

        <button
          type="button"
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
          className="inline-flex min-h-11 flex-1 items-center justify-center gap-2 rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50 sm:min-h-0 sm:flex-none"
        >
          {syncMutation.isPending ? (
            <Loader2 className="size-[15px] animate-spin" />
          ) : (
            <RefreshCw className="size-[15px]" />
          )}
          同步 CVE
        </button>
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-4 py-4 sm:px-6 md:px-8 md:py-6">
        {cveQuery.isPending ? (
          <div className="flex flex-1 items-center justify-center gap-2 font-mono text-sm text-text-muted">
            <Loader2 className="size-4 animate-spin" />
            加载中…
          </div>
        ) : cveQuery.isError ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 text-text-muted">
            <ShieldAlert className="size-6 text-danger" />
            <span className="font-mono text-sm">加载 CVE 列表失败</span>
          </div>
        ) : cves.length === 0 ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 text-text-muted">
            <ShieldAlert className="size-6 text-text-muted" />
            <span className="font-mono text-sm">暂无 CVE 记录 · 点击「同步 CVE」拉取或「手动添加」</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 text-text-muted">
            <ShieldAlert className="size-6 text-text-muted" />
            <span className="font-mono text-sm">无匹配结果</span>
          </div>
        ) : (
          filtered.map((cve) => <CveCard key={cve.id} cve={cve} />)
        )}
      </div>

      <AddCveDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        pending={addMutation.isPending}
        onSubmit={(body) => addMutation.mutate(body)}
      />
    </div>
  )
}
