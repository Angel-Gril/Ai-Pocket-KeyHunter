import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Check,
  ChevronDown,
  CircleCheck,
  Gem,
  GitBranch,
  Globe,
  KeyRound,
  Layers,
  Loader2,
  Lock,
  Play,
  Radar,
  Server,
  Square,
  Terminal,
} from "lucide-react"
import { toast } from "sonner"
import { Checkbox } from "@/components/ui/checkbox"

import {
  api,
  ApiError,
  openScanLogStream,
  type ScanLogLine,
  type GitHubPackId,
  type ManualEnrichEngine,
  type ScanMode,
  type ScanSource,
  type ScanSourceItem,
  type ScanStatusResponse,
} from "@/lib/api"
import { cn } from "@/lib/utils"
import {
  ALL_SCAN_SOURCES,
  parseSourceLabel,
  serializeSources,
  toCanonicalSourceLabel,
  toggleAllSources,
  toggleSource as toggleSourceSelection,
} from "@/lib/scan-sources"

const MAX_LINES = 200
const POLL_MS = 2000

const SOURCE_ITEMS: { value: ScanSourceItem; label: string; icon: typeof Globe }[] = [
  { value: "fofa", label: "FOFA", icon: Globe },
  { value: "shodan", label: "Shodan", icon: Radar },
  { value: "github", label: "GitHub", icon: GitBranch },
]


/** Individual provider packs (excludes the "all" shortcut). */
const GITHUB_PACK_OPTIONS: readonly { value: Exclude<GitHubPackId, "all">; label: string }[] = [
  { value: "gemini", label: "Gemini" },
  { value: "xai", label: "xAI / Grok" },
  { value: "qoder", label: "Qoder / Cantus" },
  { value: "kiro", label: "Kiro" },
  { value: "aws_bedrock", label: "AWS Bedrock" },
  { value: "cursor", label: "Cursor" },
  { value: "windsurf", label: "Windsurf" },
  { value: "deepseek", label: "DeepSeek" },
  { value: "openai", label: "OpenAI" },
  { value: "anthropic", label: "Anthropic" },
  { value: "azure_openai", label: "Azure OpenAI" },
  { value: "glm", label: "GLM" },
  { value: "kimi", label: "Kimi" },
  { value: "qwen", label: "Qwen" },
  { value: "minimax", label: "MiniMax" },
  { value: "longcat", label: "LongCat" },
  { value: "cohere", label: "Cohere" },
  { value: "replicate", label: "Replicate" },
  { value: "together", label: "Together" },
  { value: "fireworks", label: "Fireworks" },
]

const ALL_PACK_IDS = GITHUB_PACK_OPTIONS.map((p) => p.value)

function isActive(state: string | undefined): boolean {
  return state === "running" || state === "stopping"
}

function isTerminal(state: string): boolean {
  return state === "finished" || state === "interrupted" || state === "idle"
}

function stateLabel(state: string | undefined): string {
  switch (state) {
    case "running":
      return "运行中"
    case "stopping":
      return "停止中"
    case "finished":
      return "已完成"
    case "interrupted":
      return "已中断"
    default:
      return "空闲"
  }
}

const RE_LINE_DANGER = /\b(ERROR|CRITICAL|FATAL|401|403)\b|失败|中断/
const RE_LINE_WARNING = /\b(WARN|WARNING|429)\b|警告/
const RE_LINE_SUCCESS = /\b(200|saved|valid|success)\b|扫描完成/i
const RE_LINE_PHASE = /阶段 ·|发现 · 进度 ·|GitHub (lane=|file_history|code_snapshot|commit_message)/

function lineTone(line: string): string {
  if (RE_LINE_DANGER.test(line)) return "text-danger"
  if (RE_LINE_WARNING.test(line)) return "text-warning"
  if (RE_LINE_PHASE.test(line)) return "text-accent font-semibold"
  if (RE_LINE_SUCCESS.test(line)) return "text-success"
  return "text-text-secondary"
}

interface MetricCardProps {
  icon: typeof Server
  label: string
  value: string
  valueClass?: string
  iconClass?: string
}

function MetricCard({ icon: Icon, label, value, valueClass, iconClass }: Readonly<MetricCardProps>) {
  return (
    <div className="flex min-w-0 flex-1 flex-col gap-2.5 rounded-md border border-border-primary bg-surface-raised p-4 sm:p-[18px]">
      <div className="flex items-center gap-2">
        <Icon className={cn("size-[15px] shrink-0", iconClass ?? "text-text-primary")} />
        <span className="truncate font-mono text-[11px] tracking-[0.3px] text-text-muted">
          {label}
        </span>
      </div>
      <span
        className={cn(
          "font-mono text-[26px] font-semibold leading-none",
          valueClass ?? "text-text-primary",
        )}
      >
        {value}
      </span>
    </div>
  )
}

const MANUAL_ENRICH_KEY = "aipocket.manual-enrich.engines"

function readManualEnrich(): ManualEnrichEngine[] {
  try {
    const raw = window.localStorage.getItem(MANUAL_ENRICH_KEY)
    if (raw == null) return ["fofa", "shodan"]
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return ["fofa", "shodan"]
    const out: ManualEnrichEngine[] = []
    for (const item of parsed) {
      if (item === "fofa" || item === "shodan") {
        if (!out.includes(item)) out.push(item)
      }
    }
    return out
  } catch {
    return ["fofa", "shodan"]
  }
}

export interface ScanConsoleProps {
  /** Lock source selector and always start with this source (e.g. github-only page). */
  fixedSource?: ScanSource
  title?: string
  subtitle?: string
  startLabel?: string
}

export function ScanConsole({
  fixedSource,
  title = "执行扫描",
  subtitle,
  startLabel = "开始扫描",
}: Readonly<ScanConsoleProps>) {
  const queryClient = useQueryClient()
  /** Multi-select data sources (FOFA / Shodan / GitHub). Empty is invalid at start. */
  const [selectedSources, setSelectedSources] = useState<ScanSourceItem[]>(() => {
    if (fixedSource && fixedSource !== "all") return [fixedSource]
    return [...ALL_SCAN_SOURCES]
  })
  const [mode, setMode] = useState<ScanMode>("incremental")
  /** Multi-select provider packs. Empty + "all" shortcut both mean every pack. */
  const [githubPacks, setGithubPacks] = useState<GitHubPackId[]>(["deepseek", "glm", "kimi"])
  const [packDropdownOpen, setPackDropdownOpen] = useState(false)
  /** Custom hunt: reverse-lookup hostnames on FOFA/Shodan for product fingerprints. */
  const [manualEnrich, setManualEnrich] = useState<ManualEnrichEngine[]>(readManualEnrich)
  const [lines, setLines] = useState<ScanLogLine[]>([])
  /** Live phase derived from log SSE (faster than status poll). */
  const [phaseFromLogs, setPhaseFromLogs] = useState("")

  const lastSeqRef = useRef(0)
  const logViewRef = useRef<HTMLDivElement>(null)
  const packDropdownRef = useRef<HTMLDivElement>(null)

  // Keep locked source in sync if prop changes.
  useEffect(() => {
    if (fixedSource && fixedSource !== "all") setSelectedSources([fixedSource])
  }, [fixedSource])

  useEffect(() => {
    if (fixedSource !== "manual") return
    try {
      window.localStorage.setItem(MANUAL_ENRICH_KEY, JSON.stringify(manualEnrich))
    } catch {
      // ignore quota / private mode
    }
  }, [fixedSource, manualEnrich])

  // Close provider multi-select on outside click / Escape.
  useEffect(() => {
    if (!packDropdownOpen) return
    const onPointerDown = (e: MouseEvent) => {
      if (packDropdownRef.current && !packDropdownRef.current.contains(e.target as Node)) {
        setPackDropdownOpen(false)
      }
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPackDropdownOpen(false)
    }
    document.addEventListener("mousedown", onPointerDown)
    document.addEventListener("keydown", onKeyDown)
    return () => {
      document.removeEventListener("mousedown", onPointerDown)
      document.removeEventListener("keydown", onKeyDown)
    }
  }, [packDropdownOpen])

  const statusQuery = useQuery({
    queryKey: ["scan-status"],
    queryFn: () => api.scanStatus(),
    refetchInterval: (query) => (isActive(query.state.data?.state) ? 1500 : false),
  })

  const status = statusQuery.data
  const state = status?.state
  const running = isActive(state)
  const runId = status?.run_id ?? null
  const progress = status?.progress

  // Don't leave the menu open while a scan is running.
  useEffect(() => {
    if (running) setPackDropdownOpen(false)
  }, [running])

  const applyStatus = useCallback(
    (next: ScanStatusResponse) => queryClient.setQueryData(["scan-status"], next),
    [queryClient],
  )

  const appendLines = useCallback((incoming: ScanLogLine[]) => {
    const fresh = incoming.filter((l) => l.seq > lastSeqRef.current)
    if (fresh.length === 0) return
    lastSeqRef.current = fresh.reduce((max, l) => Math.max(max, l.seq), lastSeqRef.current)
    // Prefer the latest "阶段 · …" marker so the phase badge tracks SSE without waiting for /status.
    for (let i = fresh.length - 1; i >= 0; i -= 1) {
      const match = fresh[i].line.match(/阶段 ·\s*(.+)$/)
      if (match?.[1]) {
        setPhaseFromLogs(match[1].trim())
        break
      }
    }
    setLines((prev) => {
      const merged = prev.concat(fresh)
      return merged.length > MAX_LINES ? merged.slice(merged.length - MAX_LINES) : merged
    })
  }, [])


  useEffect(() => {
    if (!running) return

    let cancelled = false
    let stream: EventSource | null = null
    let pollTimer: number | null = null

    const poll = () => {
      api
        .scanLogs(lastSeqRef.current)
        .then((res) => {
          if (cancelled) return
          appendLines(res.lines)
        })
        .catch(() => {})
    }

    // Poll for the whole run. SSE lowers latency, while polling closes gaps from
    // proxies that connect successfully but buffer or drop later stream chunks.
    poll()
    pollTimer = window.setInterval(poll, POLL_MS)
    stream = openScanLogStream(lastSeqRef.current, {
      onLog: (line) => {
        if (!cancelled) appendLines([line])
      },
      onStatus: (nextState) => {
        if (!cancelled && isTerminal(nextState)) {
          void queryClient.invalidateQueries({ queryKey: ["scan-status"] })
        }
      },
      onError: () => {
        stream?.close()
        stream = null
      },
    })

    return () => {
      cancelled = true
      stream?.close()
      if (pollTimer) clearInterval(pollTimer)
    }
  }, [running, runId, status?.started_at, appendLines, queryClient])

  useEffect(() => {
    const el = logViewRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  const launchSources: ScanSourceItem[] = useMemo(() => {
    if (fixedSource && fixedSource !== "all") return [fixedSource]
    // Stable order for API + labels.
    return ALL_SCAN_SOURCES.filter((id) => selectedSources.includes(id))
  }, [fixedSource, selectedSources])

  const includesGitHub = launchSources.includes("github")

  const resolvedGithubPackIds = useMemo((): GitHubPackId[] => {
    if (!includesGitHub) return []
    if (githubPacks.includes("all")) return ["all"]
    if (githubPacks.length === 0) return []
    // Dedup while preserving order.
    const seen = new Set<string>()
    const out: GitHubPackId[] = []
    for (const id of githubPacks) {
      if (seen.has(id) || id === "all") continue
      seen.add(id)
      out.push(id)
    }
    // All individual packs selected → normalize to "all".
    if (out.length === ALL_PACK_IDS.length && ALL_PACK_IDS.every((id) => seen.has(id))) {
      return ["all"]
    }
    return out
  }, [includesGitHub, githubPacks])

  const toggleSource = useCallback((id: ScanSourceItem) => {
    setSelectedSources((prev) => toggleSourceSelection(prev, id))
  }, [])

  const selectAllSources = useCallback(() => {
    setSelectedSources((prev) => toggleAllSources(prev))
  }, [])

  const toggleGithubPack = useCallback((packId: Exclude<GitHubPackId, "all">) => {
    setGithubPacks((prev) => {
      // Expanding "all" into the concrete list so unchecking one pack works.
      const base: GitHubPackId[] = prev.includes("all")
        ? [...ALL_PACK_IDS]
        : prev.filter((p): p is Exclude<GitHubPackId, "all"> => p !== "all")
      if (base.includes(packId)) {
        return base.filter((p) => p !== packId)
      }
      return [...base, packId]
    })
  }, [])

  /** Toggle select-all: second click clears every pack. */
  const toggleAllGithubPacks = useCallback(() => {
    setGithubPacks((prev) => {
      const isAll =
        prev.includes("all") ||
        (prev.length === ALL_PACK_IDS.length && ALL_PACK_IDS.every((id) => prev.includes(id)))
      return isAll ? [] : ["all"]
    })
  }, [])

  const isManualLane = fixedSource === "manual" || launchSources.includes("manual")

  const toggleManualEnrich = useCallback((engine: ManualEnrichEngine) => {
    setManualEnrich((prev) =>
      prev.includes(engine) ? prev.filter((e) => e !== engine) : [...prev, engine],
    )
  }, [])

  const startMutation = useMutation({
    mutationFn: () => {
      if (launchSources.length === 0) {
        return Promise.reject(new Error("请至少选择一个数据源"))
      }
      if (includesGitHub && resolvedGithubPackIds.length === 0) {
        return Promise.reject(new Error("请至少选择一个 GitHub Provider 包"))
      }
      const serialized = serializeSources(launchSources)
      if (!serialized) {
        return Promise.reject(new Error("请至少选择一个数据源"))
      }
      const enrich =
        isManualLane && manualEnrich.length > 0
          ? ([...manualEnrich].sort() as ManualEnrichEngine[])
          : []
      return api.scanStart(
        serialized.source,
        mode,
        resolvedGithubPackIds,
        serialized.sources,
        enrich,
      )
    },
    onSuccess: (next) => {
      lastSeqRef.current = 0
      setLines([])
      setPhaseFromLogs("")
      applyStatus(next)
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) {
        toast.info("扫描已在运行")
        void statusQuery.refetch()
        return
      }
      toast.error(err instanceof Error ? err.message : "启动扫描失败")
    },
  })

  const stopMutation = useMutation({
    mutationFn: () => api.scanStop(),
    onSuccess: (next) => {
      applyStatus(next)
      toast.info("已发送停止请求")
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) {
        toast.info("当前没有正在运行的扫描")
        void statusQuery.refetch()
        return
      }
      toast.error(err instanceof Error ? err.message : "停止扫描失败")
    },
  })

  const total = progress?.candidates ?? 0
  const validated = progress?.active_requests ?? 0
  const percent = useMemo(() => {
    if (total <= 0) return 0
    return Math.min(100, Math.round((validated / total) * 100))
  }, [total, validated])
  const indeterminate = running && total <= 0
  const phaseLabel = useMemo(() => {
    const phase = (phaseFromLogs || status?.phase || "").trim()
    if (phase) return phase
    if (running) return "运行中…"
    if (state === "finished") return "已完成"
    if (state === "interrupted") return "已中断"
    return "等待开始"
  }, [phaseFromLogs, status?.phase, running, state])

  const activeSources: ScanSourceItem[] = running
    ? parseSourceLabel(status?.source ?? toCanonicalSourceLabel(launchSources))
    : launchSources
  const activeAllSources =
    activeSources.length === ALL_SCAN_SOURCES.length &&
    ALL_SCAN_SOURCES.every((id) => activeSources.includes(id))
  // While editing, drive UI from local githubPacks so empty ≠ "all".
  // While running, prefer server-reported pack ids.
  const activeGithubPackIds = running
    ? (status?.github_pack_ids?.length ? status.github_pack_ids : resolvedGithubPackIds)
    : resolvedGithubPackIds
  const allPacksSelected = useMemo(() => {
    if (running) {
      return (
        activeGithubPackIds.includes("all") ||
        (activeGithubPackIds.length === ALL_PACK_IDS.length &&
          ALL_PACK_IDS.every((id) => activeGithubPackIds.includes(id)))
      )
    }
    return (
      githubPacks.includes("all") ||
      (githubPacks.length === ALL_PACK_IDS.length &&
        ALL_PACK_IDS.every((id) => githubPacks.includes(id)))
    )
  }, [running, activeGithubPackIds, githubPacks])
  const selectedPackCount = allPacksSelected
    ? ALL_PACK_IDS.length
    : running
      ? activeGithubPackIds.filter((id) => id !== "all").length
      : githubPacks.filter((id) => id !== "all").length
  const activeGithubPackLabel = useMemo(() => {
    if (allPacksSelected) return "全部 Provider"
    if (selectedPackCount === 0) return "请选择 Provider"
    const sourceIds = running ? activeGithubPackIds : githubPacks
    const labels = GITHUB_PACK_OPTIONS.filter((p) => sourceIds.includes(p.value)).map((p) => p.label)
    if (labels.length === 0) return "请选择 Provider"
    if (labels.length <= 3) return labels.join("、")
    return `${labels.slice(0, 2).join("、")} 等 ${labels.length} 个`
  }, [allPacksSelected, selectedPackCount, running, activeGithubPackIds, githubPacks])
  const stopping = state === "stopping"
  const locked = Boolean(fixedSource)

  const defaultSubtitle = locked
    ? `固定数据源 ${fixedSource} · 全局单例 · 结果入库后与其它来源一致展示 · ${stateLabel(state)}`
    : `全局单例 · 同一时刻只允许一个扫描运行 · ${stateLabel(state)}`

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-col gap-3 border-b border-border-primary px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-6 md:px-8 md:py-5">
        <div className="flex flex-1 flex-col gap-[3px]">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">{title}</h1>
          <p className="font-mono text-xs text-text-muted">{subtitle ?? defaultSubtitle}</p>
        </div>
        {running ? (
          <button
            type="button"
            onClick={() => stopMutation.mutate()}
            disabled={stopMutation.isPending || stopping}
            className="inline-flex min-h-11 items-center justify-center gap-[7px] rounded-[4px] border border-danger bg-danger-dim px-4 py-[9px] text-[13px] font-semibold text-danger transition-opacity hover:opacity-90 disabled:opacity-50 sm:min-h-0"
          >
            {stopMutation.isPending || stopping ? (
              <Loader2 className="size-[14px] animate-spin" />
            ) : (
              <Square className="size-[14px]" />
            )}
            停止扫描
          </button>
        ) : (
          <button
            type="button"
            onClick={() => startMutation.mutate()}
            disabled={startMutation.isPending || launchSources.length === 0}
            className="inline-flex min-h-11 items-center justify-center gap-[7px] rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50 sm:min-h-0"
          >
            {startMutation.isPending ? (
              <Loader2 className="size-[14px] animate-spin" />
            ) : (
              <Play className="size-[14px]" />
            )}
            {startLabel}
          </button>
        )}
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 py-4 sm:gap-5 sm:px-6 md:px-8 md:py-6">
        {locked ? (
          <div className="flex flex-wrap items-center gap-3.5">
            <span className="font-mono text-xs text-text-muted">数据源</span>
            <span className="inline-flex items-center gap-2 rounded-[4px] border border-accent bg-accent-dim px-4 py-[9px] text-[13px] font-semibold text-accent">
              {fixedSource === "manual" ? (
                <Server className="size-[15px]" />
              ) : (
                <GitBranch className="size-[15px]" />
              )}
              {fixedSource === "manual"
                ? "自定义狩猎"
                : fixedSource === "github"
                  ? "GitHub"
                  : fixedSource}
            </span>
            <span className="font-mono text-[11px] text-text-muted">
              {fixedSource === "manual"
                ? "本页固定为 source=manual · 探测已入库地址 · 可开启域名反查 FOFA / Shodan 补指纹"
                : `本页固定为 source=${fixedSource} · 组合扫描请用「执行扫描」多选数据源`}
            </span>
            {running ? (
              <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] text-text-muted">
                <Lock className="size-[13px]" />
                运行中不可修改
              </span>
            ) : null}
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-3.5">
            <span className="font-mono text-xs text-text-muted">数据源</span>
            <button
              type="button"
              disabled={running}
              onClick={selectAllSources}
              className={cn(
                "inline-flex items-center gap-2 rounded-[4px] border px-4 py-[9px] text-[13px] transition-colors",
                activeAllSources
                  ? "border-accent bg-accent-dim font-semibold text-accent"
                  : "border-border-primary bg-surface-raised text-text-secondary hover:text-text-primary",
                running && "cursor-not-allowed opacity-50",
              )}
            >
              <Layers className="size-[15px]" />
              全部
            </button>
            {SOURCE_ITEMS.map(({ value, label, icon: Icon }) => {
              const selected = activeSources.includes(value)
              return (
                <button
                  key={value}
                  type="button"
                  disabled={running}
                  aria-pressed={selected}
                  onClick={() => toggleSource(value)}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-[4px] border px-4 py-[9px] text-[13px] transition-colors",
                    selected
                      ? "border-accent bg-accent-dim font-semibold text-accent"
                      : "border-border-primary bg-surface-raised text-text-secondary hover:text-text-primary",
                    running && "cursor-not-allowed opacity-50",
                  )}
                >
                  <Icon className="size-[15px]" />
                  {label}
                </button>
              )
            })}
            {!running ? (
              <span className="font-mono text-[11px] text-text-muted">
                {launchSources.length === 0
                  ? "请至少选择一个数据源"
                  : "可多选 · 例如只跑 FOFA + Shodan 全量"}
              </span>
            ) : null}
            {running ? (
              <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] text-text-muted">
                <Lock className="size-[13px]" />
                运行中不可修改
              </span>
            ) : null}
          </div>
        )}

        {fixedSource === "manual" ? (
          <div className="flex flex-wrap items-center gap-3.5">
            <span className="font-mono text-xs text-text-muted">域名反查</span>
            {(
              [
                { value: "fofa" as const, label: "FOFA" },
                { value: "shodan" as const, label: "Shodan" },
              ] as const
            ).map(({ value, label }) => {
              const selected = manualEnrich.includes(value)
              return (
                <button
                  key={value}
                  type="button"
                  disabled={running}
                  aria-pressed={selected}
                  onClick={() => toggleManualEnrich(value)}
                  className={cn(
                    "inline-flex items-center gap-2 rounded-[4px] border px-4 py-[9px] text-[13px] transition-colors",
                    selected
                      ? "border-accent bg-accent-dim font-semibold text-accent"
                      : "border-border-primary bg-surface-raised text-text-secondary hover:text-text-primary",
                    running && "cursor-not-allowed opacity-50",
                  )}
                >
                  <Radar className="size-[15px]" />
                  {label}
                </button>
              )
            })}
            <span className="font-mono text-[11px] text-text-muted">
              {manualEnrich.length === 0
                ? "关闭时仅探测已入库 URL（无产品指纹）"
                : "按域名反查 title/banner · 补 NewAPI 等产品识别 · 消耗对应 API 额度"}
            </span>
          </div>
        ) : null}

        {activeSources.includes("github") ? (
          <div className="flex flex-wrap items-center gap-3.5">
            <span className="font-mono text-xs text-text-muted">GitHub Provider 包</span>
            <div ref={packDropdownRef} className="relative">
              <button
                type="button"
                disabled={running}
                aria-haspopup="listbox"
                aria-expanded={packDropdownOpen}
                onClick={() => setPackDropdownOpen((o) => !o)}
                className={cn(
                  "inline-flex h-11 min-w-0 max-w-full flex-1 items-center justify-between gap-2 rounded-[4px] border px-3 text-[13px] transition-colors sm:h-9 sm:min-w-[220px] sm:max-w-[360px] sm:flex-none",
                  packDropdownOpen || (!running && !allPacksSelected && githubPacks.length > 0)
                    ? "border-accent bg-accent-dim font-semibold text-accent"
                    : "border-border-primary bg-surface-raised text-text-secondary hover:text-text-primary",
                  running && "cursor-not-allowed opacity-50",
                )}
              >
                <span className="truncate">{activeGithubPackLabel}</span>
                <ChevronDown
                  className={cn(
                    "size-4 shrink-0 opacity-60 transition-transform",
                    packDropdownOpen && "rotate-180",
                  )}
                />
              </button>
              {packDropdownOpen && !running ? (
                <div
                  role="listbox"
                  aria-multiselectable
                  className="absolute top-[calc(100%+4px)] left-0 z-50 w-[min(280px,calc(100vw-2rem))] overflow-hidden rounded-md border border-border-primary bg-surface-raised shadow-lg"
                >
                  <div className="max-h-[320px] overflow-y-auto p-1">
                    <button
                      type="button"
                      role="option"
                      aria-selected={allPacksSelected}
                      onClick={toggleAllGithubPacks}
                      className={cn(
                        "flex w-full items-center gap-2.5 rounded-sm px-2.5 py-2 text-left text-[13px] transition-colors hover:bg-surface-inset",
                        allPacksSelected
                          ? "font-semibold text-accent"
                          : "text-text-secondary",
                      )}
                    >
                      <span
                        className={cn(
                          "flex size-4 shrink-0 items-center justify-center rounded-[4px] border",
                          allPacksSelected
                            ? "border-accent bg-accent text-accent-text"
                            : "border-border-primary bg-surface-base",
                        )}
                      >
                        {allPacksSelected ? <Check className="size-3" /> : null}
                      </span>
                      全部 Provider
                    </button>
                    <div className="my-1 h-px bg-border-primary" />
                    {GITHUB_PACK_OPTIONS.map((pack) => {
                      const checked = allPacksSelected || githubPacks.includes(pack.value)
                      return (
                        <button
                          key={pack.value}
                          type="button"
                          role="option"
                          aria-selected={checked}
                          onClick={() => toggleGithubPack(pack.value)}
                          className={cn(
                            "flex w-full items-center gap-2.5 rounded-sm px-2.5 py-2 text-left text-[13px] transition-colors hover:bg-surface-inset",
                            checked ? "font-medium text-accent" : "text-text-secondary",
                          )}
                        >
                          <Checkbox
                            checked={checked}
                            tabIndex={-1}
                            className="pointer-events-none"
                            aria-hidden
                          />
                          {pack.label}
                        </button>
                      )
                    })}
                  </div>
                  <div className="border-t border-border-primary px-2.5 py-1.5 font-mono text-[11px] text-text-muted">
                    已选 {selectedPackCount} / {ALL_PACK_IDS.length}
                  </div>
                </div>
              ) : null}
            </div>
            {running ? (
              <span className="font-mono text-[11px] text-text-muted">
                运行中不可修改
              </span>
            ) : (
              <span className="font-mono text-[11px] text-text-muted">
                可多选任意子集；按选择顺序依次狩猎，预算按 pack 分片。建议先跑 1～3 个包避免限流。
              </span>
            )}
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-3.5">
          <span className="font-mono text-xs text-text-muted">扫描模式</span>
          {(["incremental", "full"] as const).map((value) => (
            <button
              key={value}
              type="button"
              disabled={running}
              onClick={() => setMode(value)}
              className={cn(
                "rounded-[4px] border px-4 py-[9px] text-[13px] transition-colors",
                mode === value
                  ? "border-accent bg-accent-dim font-semibold text-accent"
                  : "border-border-primary bg-surface-raised text-text-secondary",
                running && "cursor-not-allowed opacity-50",
              )}
            >
              {value === "incremental" ? "增量扫描" : "全量扫描"}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 sm:gap-4 xl:grid-cols-5">
          <MetricCard icon={Server} label="原始命中" value={String(progress?.raw_hits ?? 0)} />
          <MetricCard icon={Layers} label="唯一目标" value={String(progress?.unique_targets ?? 0)} />
          <MetricCard
            icon={KeyRound}
            iconClass="text-info"
            valueClass="text-info"
            label="主动请求"
            value={`${validated} / ${total}`}
          />
          <MetricCard
            icon={CircleCheck}
            iconClass="text-success"
            valueClass="text-success"
            label="最终可用"
            value={String(progress?.final_verified ?? 0)}
          />
          <MetricCard
            icon={Gem}
            iconClass="text-warning"
            valueClass="text-warning"
            label="高价值"
            value={String(progress?.high_value_final ?? 0)}
          />
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <div className="font-mono text-[11px] text-text-muted">当前阶段</div>
              <div
                className={cn(
                  "mt-0.5 font-mono text-xs font-semibold leading-snug break-all",
                  running ? "text-accent" : "text-text-secondary",
                )}
                title={phaseLabel}
              >
                {phaseLabel}
              </div>
            </div>
            <span className="shrink-0 pt-3 font-mono text-xs font-semibold text-accent">
              {indeterminate ? "发现中" : `${percent}%`}
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-surface-inset">
            <div
              className={cn(
                "h-full rounded-full bg-accent transition-[width] duration-500",
                indeterminate && "w-1/3 animate-pulse",
              )}
              style={indeterminate ? undefined : { width: `${percent}%` }}
            />
          </div>
          {running && total <= 0 ? (
            <p className="font-mono text-[11px] leading-relaxed text-text-muted">
              验证进度在候选密钥产生后才会更新百分比；当前仍在发现阶段，请看下方实时日志中的「阶段 · …」行。
            </p>
          ) : null}
        </div>

        <div className="flex min-h-[300px] flex-1 flex-col overflow-hidden rounded-md border border-border-primary bg-surface-inset sm:min-h-[360px]">
          <div className="flex items-center gap-2.5 border-b border-border-subtle bg-surface-raised px-4 py-2.5">
            <Terminal className="size-[14px] text-accent" />
            <span className="flex-1 font-mono text-xs font-semibold text-text-secondary">
              实时日志 · 显示最近 {MAX_LINES} 行 (完整日志已落盘)
            </span>
            {running ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-accent-dim px-2.5 py-[3px] font-mono text-[11px] font-semibold text-accent">
                <span className="size-[7px] shrink-0 animate-pulse rounded-full bg-accent" />
                LIVE
              </span>
            ) : null}
          </div>
          {running || status?.phase ? (
            <div className="border-b border-border-subtle bg-accent-dim/40 px-4 py-2">
              <span className="font-mono text-[11px] text-text-muted">阶段 · </span>
              <span className="font-mono text-xs font-semibold text-accent break-all">
                {phaseLabel}
              </span>
            </div>
          ) : null}
          <div ref={logViewRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
            {lines.length === 0 ? (
              <div className="flex h-full items-center justify-center font-mono text-xs text-text-muted">
                {running
                  ? "等待日志输出… 后端正在初始化 / 进入发现阶段"
                  : "扫描未运行 · 点击右上角开始扫描"}
              </div>
            ) : (
              <div className="flex flex-col gap-[3px]">
                {lines.map((l) => (
                  <p
                    key={l.seq}
                    className={cn(
                      "font-mono text-xs leading-relaxed break-all whitespace-pre-wrap",
                      lineTone(l.line),
                    )}
                  >
                    {l.line}
                  </p>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function ScanPage() {
  return <ScanConsole />
}
