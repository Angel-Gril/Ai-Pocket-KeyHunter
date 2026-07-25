import { NavLink } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import {
  Bug,
  Gem,
  GitBranch,
  KeyRound,
  LayoutList,
  type LucideIcon,
  Moon,
  Radar,
  Server,
  Settings,
  ShieldAlert,
  Sun,
  X,
} from "lucide-react"
import { api, type ScanStatusResponse } from "@/lib/api"
import { useTheme } from "@/providers/theme-provider"
import { cn } from "@/lib/utils"
import { NAV_ITEMS } from "@/lib/navigation"

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
}

const NAV_ICONS: Record<string, LucideIcon> = {
  "/history": LayoutList,
  "/keys": KeyRound,
  "/high-value": Gem,
  "/scan": Radar,
  "/github": GitBranch,
  "/manual": Server,
  "/cve": ShieldAlert,
  "/honeypot": Bug,
  "/settings": Settings,
}

const SIDEBAR_ITEMS: NavItem[] = NAV_ITEMS.map((item) => ({
  ...item,
  icon: NAV_ICONS[item.to]!,
}))

function statusDisplay(status: ScanStatusResponse | undefined): {
  dot: string
  pulse: boolean
  label: string
  hint: string
} {
  const state = status?.state ?? "idle"
  if (state === "running" || state === "stopping") {
    const { valid, total } = status?.progress ?? { valid: 0, total: 0 }
    return {
      dot: "bg-success",
      pulse: true,
      label: state === "stopping" ? "STOPPING · 停止中" : "RUNNING · 扫描中",
      hint: total > 0 ? `有效 ${valid} / ${total}` : `有效 ${valid}`,
    }
  }
  if (state === "finished") {
    return { dot: "bg-success", pulse: false, label: "FINISHED · 完成", hint: formatHint(status) }
  }
  if (state === "interrupted") {
    return { dot: "bg-warning", pulse: false, label: "STOPPED · 已停止", hint: formatHint(status) }
  }
  return { dot: "bg-text-muted", pulse: false, label: "IDLE · 空闲", hint: formatHint(status) }
}

function formatHint(status: ScanStatusResponse | undefined): string {
  const stamp = status?.finished_at ?? status?.started_at
  if (!stamp) return "尚无扫描记录"
  const date = new Date(stamp)
  if (Number.isNaN(date.getTime())) return "尚无扫描记录"
  const pad = (n: number) => String(n).padStart(2, "0")
  return `上次扫描 ${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

interface SidebarProps {
  mobileOpen?: boolean
  onMobileClose?: () => void
}

export function Sidebar({ mobileOpen = false, onMobileClose }: Readonly<SidebarProps>) {
  const { theme, toggleTheme } = useTheme()
  const { data: status } = useQuery({
    queryKey: ["scan-status"],
    queryFn: ({ signal }) => api.scanStatus(signal),
    // Poll fast while a scan is active; back off when idle to cut needless churn.
    refetchInterval: (query) => {
      const state = query.state.data?.state
      return state === "running" || state === "stopping" ? 5000 : 20000
    },
  })

  const display = statusDisplay(status)

  return (
    <aside
      aria-label="主导航"
      className={cn(
        "fixed inset-y-0 left-0 z-50 flex h-dvh w-[min(19rem,86vw)] shrink-0 flex-col border-r border-border-primary bg-surface-raised transition-transform duration-200 md:static md:h-full md:w-62 md:translate-x-0",
        mobileOpen ? "translate-x-0" : "invisible -translate-x-full md:visible",
      )}
    >
      <div className="flex min-h-14 items-center gap-2.5 border-b border-border-subtle px-4 md:px-5 md:py-6">
        <span className="size-2.5 rounded-full bg-accent" />
        <span className="flex-1 font-mono text-[17px] font-semibold tracking-[-0.3px] text-text-primary">
          aipocket
        </span>
        <button
          type="button"
          onClick={onMobileClose}
          aria-label="关闭导航"
          className="flex size-11 items-center justify-center rounded-md text-text-secondary hover:bg-surface-overlay hover:text-text-primary md:hidden"
        >
          <X className="size-5" />
        </button>
      </div>

      <nav className="flex flex-col gap-1 overflow-y-auto px-3 py-3 md:py-4">
        {SIDEBAR_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            onClick={onMobileClose}
            className={({ isActive }) =>
              cn(
                "flex min-h-11 items-center gap-3 rounded-sm px-3 py-2.5 text-sm transition-colors",
                isActive
                  ? "bg-accent-dim font-semibold text-accent"
                  : "text-text-secondary hover:text-text-primary",
              )
            }
          >
            <Icon className="size-[18px]" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="flex-1" />

      <div className="flex flex-col gap-2 border-t border-border-subtle px-5 py-4">
        <div className="flex items-center gap-2">
          <span className={cn("size-2 rounded-full", display.dot, display.pulse && "animate-pulse")} />
          <span className="font-mono text-xs text-text-secondary">{display.label}</span>
        </div>
        <span className="font-mono text-[11px] text-text-muted">{display.hint}</span>
      </div>

      <div className="border-t border-border-subtle px-3 py-2 md:py-3">
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "切换到浅色主题" : "切换到深色主题"}
          className="flex min-h-11 w-full items-center gap-3 rounded-sm px-3 py-2.5 text-sm text-text-secondary transition-colors hover:bg-surface-overlay hover:text-text-primary"
        >
          {theme === "dark" ? <Sun className="size-[18px]" /> : <Moon className="size-[18px]" />}
          {theme === "dark" ? "浅色主题" : "深色主题"}
        </button>
      </div>
    </aside>
  )
}
