import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CircleCheck,
  Gem,
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

import {
  api,
  ApiError,
  openScanLogStream,
  type ScanLogLine,
  type ScanSource,
  type ScanStatusResponse,
} from "@/lib/api"
import { cn } from "@/lib/utils"

const MAX_LINES = 200
const POLL_MS = 2000

const SOURCES: { value: ScanSource; label: string; icon: typeof Globe }[] = [
  { value: "all", label: "全部", icon: Layers },
  { value: "fofa", label: "FOFA", icon: Globe },
  { value: "shodan", label: "Shodan", icon: Radar },
]

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

const RE_LINE_DANGER = /\b(ERROR|CRITICAL|FATAL|401|403)\b/
const RE_LINE_WARNING = /\b(WARN|WARNING|429)\b/
const RE_LINE_SUCCESS = /\b(200|saved|valid|success)\b/i

function lineTone(line: string): string {
  if (RE_LINE_DANGER.test(line)) return "text-danger"
  if (RE_LINE_WARNING.test(line)) return "text-warning"
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
    <div className="flex flex-1 flex-col gap-2.5 rounded-md border border-border-primary bg-surface-raised p-[18px]">
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

export default function ScanPage() {
  const queryClient = useQueryClient()
  const [source, setSource] = useState<ScanSource>("all")
  const [lines, setLines] = useState<ScanLogLine[]>([])

  const lastSeqRef = useRef(0)
  const logViewRef = useRef<HTMLDivElement>(null)

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

  const applyStatus = useCallback(
    (next: ScanStatusResponse) => queryClient.setQueryData(["scan-status"], next),
    [queryClient],
  )

  const appendLines = useCallback((incoming: ScanLogLine[]) => {
    const fresh = incoming.filter((l) => l.seq > lastSeqRef.current)
    if (fresh.length === 0) return
    lastSeqRef.current = fresh.reduce((max, l) => Math.max(max, l.seq), lastSeqRef.current)
    setLines((prev) => {
      const merged = prev.concat(fresh)
      return merged.length > MAX_LINES ? merged.slice(merged.length - MAX_LINES) : merged
    })
  }, [])

  useEffect(() => {
    lastSeqRef.current = 0
    setLines([])
  }, [runId])

  useEffect(() => {
    if (!running) return

    let cancelled = false
    let stream: EventSource | null = null
    let pollTimer: ReturnType<typeof setInterval> | null = null

    const stopPolling = () => {
      if (pollTimer) {
        clearInterval(pollTimer)
        pollTimer = null
      }
    }

    const poll = () => {
      api
        .scanLogs(lastSeqRef.current)
        .then((res) => {
          if (cancelled) return
          appendLines(res.lines)
        })
        .catch(() => {})
    }

    const startPolling = () => {
      if (pollTimer) return
      poll()
      pollTimer = setInterval(poll, POLL_MS)
    }

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
        if (cancelled) return
        stream?.close()
        stream = null
        startPolling()
      },
    })

    return () => {
      cancelled = true
      stream?.close()
      stopPolling()
    }
  }, [running, runId, appendLines, queryClient])

  useEffect(() => {
    const el = logViewRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  const startMutation = useMutation({
    mutationFn: () => api.scanStart(source),
    onSuccess: applyStatus,
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

  const activeSource = running ? ((status?.source as ScanSource | undefined) ?? source) : source
  const stopping = state === "stopping"

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-border-primary px-8 py-5">
        <div className="flex flex-1 flex-col gap-[3px]">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">执行扫描</h1>
          <p className="font-mono text-xs text-text-muted">
            全局单例 · 同一时刻只允许一个扫描运行 · {stateLabel(state)}
          </p>
        </div>
        {running ? (
          <button
            type="button"
            onClick={() => stopMutation.mutate()}
            disabled={stopMutation.isPending || stopping}
            className="inline-flex items-center gap-[7px] rounded-[4px] border border-danger bg-danger-dim px-4 py-[9px] text-[13px] font-semibold text-danger transition-opacity hover:opacity-90 disabled:opacity-50"
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
            disabled={startMutation.isPending}
            className="inline-flex items-center gap-[7px] rounded-[4px] bg-accent px-4 py-[9px] text-[13px] font-semibold text-accent-text transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {startMutation.isPending ? (
              <Loader2 className="size-[14px] animate-spin" />
            ) : (
              <Play className="size-[14px]" />
            )}
            开始扫描
          </button>
        )}
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-5 px-8 py-6">
        <div className="flex items-center gap-3.5">
          <span className="font-mono text-xs text-text-muted">数据源</span>
          {SOURCES.map(({ value, label, icon: Icon }) => {
            const selected = activeSource === value
            return (
              <button
                key={value}
                type="button"
                disabled={running}
                onClick={() => setSource(value)}
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
          {running ? (
            <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[11px] text-text-muted">
              <Lock className="size-[13px]" />
              运行中不可修改
            </span>
          ) : null}
        </div>

        <div className="flex gap-4">
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
          <div className="flex items-center">
            <span className="flex-1 font-mono text-xs text-text-secondary">进度 · 验证 credentials</span>
            <span className="font-mono text-xs font-semibold text-accent">
              {indeterminate ? "—" : `${percent}%`}
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
        </div>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-border-primary bg-surface-inset">
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
          <div ref={logViewRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
            {lines.length === 0 ? (
              <div className="flex h-full items-center justify-center font-mono text-xs text-text-muted">
                {running ? "等待日志输出…" : "扫描未运行 · 点击右上角开始扫描"}
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
