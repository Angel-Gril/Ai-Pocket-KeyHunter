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
  PanelLeftClose,
  PanelLeftOpen,
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
import { NAV_ITEMS, preloadNavPath, type NavPath } from "@/lib/navigation"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

interface NavItem {
  to: NavPath
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
  collapsed?: boolean
  onCollapsedChange?: (collapsed: boolean) => void
  onMobileClose?: () => void
}

export function Sidebar({
  collapsed = false,
  mobileOpen = false,
  onCollapsedChange,
  onMobileClose,
}: Readonly<SidebarProps>) {
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
      data-collapsed={collapsed}
      className={cn(
        "fixed inset-y-0 left-0 z-50 flex h-dvh w-[min(19rem,86vw)] shrink-0 flex-col border-r border-border-primary bg-surface-raised transition-[width,transform] duration-200 md:static md:h-full md:translate-x-0",
        collapsed ? "md:w-[76px]" : "md:w-62",
        mobileOpen ? "translate-x-0" : "invisible -translate-x-full md:visible",
      )}
    >
      <div className={cn("flex min-h-14 items-center gap-2.5 border-b border-border-subtle px-4 md:py-6", collapsed ? "md:px-3" : "md:px-5")}>
        <span className="size-2.5 shrink-0 rounded-full bg-accent" />
        <span className={cn("flex-1 font-mono text-[17px] font-semibold tracking-[-0.3px] text-text-primary", collapsed && "md:hidden")}>
          aipocket
        </span>
        <button
          type="button"
          onClick={() => onCollapsedChange?.(!collapsed)}
          aria-label={collapsed ? "展开侧边栏" : "收起侧边栏"}
          aria-expanded={!collapsed}
          className="hidden size-8 shrink-0 items-center justify-center rounded-md text-text-muted transition-colors hover:bg-surface-overlay hover:text-text-primary md:flex"
        >
          {collapsed ? <PanelLeftOpen className="size-[18px]" /> : <PanelLeftClose className="size-[18px]" />}
        </button>
        <button
          type="button"
          onClick={onMobileClose}
          aria-label="关闭导航"
          className="ml-auto flex size-11 items-center justify-center rounded-md text-text-secondary hover:bg-surface-overlay hover:text-text-primary md:hidden"
        >
          <X className="size-5" />
        </button>
      </div>

      <nav className={cn("flex flex-col gap-1 overflow-y-auto px-3 py-3 md:py-4", collapsed && "md:px-2")}>
        {SIDEBAR_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            onClick={onMobileClose}
            onPointerEnter={() => preloadNavPath(to)}
            onFocus={() => preloadNavPath(to)}
            aria-label={collapsed ? label : undefined}
            title={collapsed ? label : undefined}
            className={({ isActive }) =>
              cn(
                "flex min-h-11 items-center gap-3 rounded-sm px-3 py-2.5 text-sm transition-colors",
                collapsed && "md:justify-center md:px-0",
                isActive
                  ? "bg-accent-dim font-semibold text-accent"
                  : "text-text-secondary hover:bg-surface-overlay hover:text-text-primary",
              )
            }
          >
            <Icon className="size-[18px] shrink-0" />
            <span className={cn("whitespace-nowrap", collapsed && "md:hidden")}>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="flex-1" />

      <Tooltip>
        <TooltipTrigger asChild>
          <div className={cn("flex flex-col gap-2 border-t border-border-subtle px-5 py-4", collapsed && "md:items-center md:px-2")}>
            <div className="flex items-center gap-2">
              <span className={cn("size-2 shrink-0 rounded-full", display.dot, display.pulse && "animate-pulse")} />
              <span className={cn("font-mono text-xs text-text-secondary", collapsed && "md:hidden")}>{display.label}</span>
            </div>
            <span className={cn("font-mono text-[11px] text-text-muted", collapsed && "md:hidden")}>{display.hint}</span>
          </div>
        </TooltipTrigger>
        {collapsed ? <TooltipContent side="right" sideOffset={8}>{display.label} · {display.hint}</TooltipContent> : null}
      </Tooltip>

      <div className={cn("border-t border-border-subtle px-3 py-2 md:py-3", collapsed && "md:px-2")}>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={theme === "dark" ? "切换到浅色主题" : "切换到深色主题"}
              className={cn(
                "flex min-h-11 w-full items-center gap-3 rounded-sm px-3 py-2.5 text-sm text-text-secondary transition-colors hover:bg-surface-overlay hover:text-text-primary",
                collapsed && "md:justify-center md:px-0",
              )}
            >
              {theme === "dark" ? <Sun className="size-[18px] shrink-0" /> : <Moon className="size-[18px] shrink-0" />}
              <span className={cn(collapsed && "md:hidden")}>{theme === "dark" ? "浅色主题" : "深色主题"}</span>
            </button>
          </TooltipTrigger>
          {collapsed ? <TooltipContent side="right" sideOffset={8}>{theme === "dark" ? "浅色主题" : "深色主题"}</TooltipContent> : null}
        </Tooltip>
      </div>
    </aside>
  )
}
