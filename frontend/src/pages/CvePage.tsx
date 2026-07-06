import { useMemo } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link2, Loader2, RefreshCw, ShieldAlert, TriangleAlert } from "lucide-react"
import { toast } from "sonner"

import { api, ApiError, type CveRecord } from "@/lib/api"
import { cn } from "@/lib/utils"

interface NormalCve {
  id: string
  title: string
  type: string
  description: string
  sourceUrl: string
  severity: "high" | "medium" | "low"
}

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

  return { id, title, type, description, sourceUrl, severity }
}

function CveCard({ cve }: Readonly<{ cve: NormalCve }>) {
  const meta = SEVERITY_META[cve.severity]
  return (
    <article className="flex flex-col gap-2.5 rounded-md border border-border-primary bg-surface-raised p-[18px]">
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

export default function CvePage() {
  const queryClient = useQueryClient()

  const cveQuery = useQuery({
    queryKey: ["cve"],
    queryFn: api.getCve,
  })

  const cves = useMemo(
    () => (cveQuery.data?.cves ?? []).map(normalize),
    [cveQuery.data],
  )

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

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-border-primary px-8 py-5">
        <div className="flex flex-1 flex-col gap-[3px]">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">CVE 库</h1>
          <p className="font-mono text-xs text-text-muted">
            sources/cve_2026_ai.json · {cves.length} 条 · 面向 AI 网关的凭据泄露漏洞
          </p>
        </div>
        <button
          type="button"
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
          className="inline-flex items-center gap-2 rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {syncMutation.isPending ? (
            <Loader2 className="size-[15px] animate-spin" />
          ) : (
            <RefreshCw className="size-[15px]" />
          )}
          同步 CVE
        </button>
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-8 py-6">
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
            <span className="font-mono text-sm">暂无 CVE 记录 · 点击「同步 CVE」拉取</span>
          </div>
        ) : (
          cves.map((cve) => <CveCard key={cve.id} cve={cve} />)
        )}
      </div>
    </div>
  )
}
