import { useState } from "react"
import { Menu } from "lucide-react"
import { Outlet, useLocation } from "react-router-dom"
import { Sidebar } from "@/components/sidebar"
import { navLabelForPath } from "@/lib/navigation"

export function AppLayout() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const location = useLocation()

  return (
    <div className="flex h-dvh w-full overflow-hidden bg-surface-base text-text-primary">
      <Sidebar mobileOpen={mobileNavOpen} onMobileClose={() => setMobileNavOpen(false)} />
      {mobileNavOpen ? (
        <button
          type="button"
          aria-label="关闭导航"
          onClick={() => setMobileNavOpen(false)}
          className="fixed inset-0 z-40 bg-black/55 backdrop-blur-[1px] md:hidden"
        />
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border-primary bg-surface-raised px-3 md:hidden">
          <button
            type="button"
            aria-label="打开导航"
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen(true)}
            className="flex size-11 items-center justify-center rounded-md text-text-secondary transition-colors hover:bg-surface-overlay hover:text-text-primary"
          >
            <Menu className="size-5" />
          </button>
          <span className="min-w-0 flex-1 truncate text-sm font-semibold">
            {navLabelForPath(location.pathname)}
          </span>
          <span className="font-mono text-xs font-semibold text-accent">aipocket</span>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto overscroll-contain">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
