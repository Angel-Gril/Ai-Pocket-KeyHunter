import { Outlet } from "react-router-dom"
import { Sidebar } from "@/components/sidebar"

export function AppLayout() {
  return (
    <div className="flex h-screen w-full overflow-hidden bg-surface-base text-text-primary">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}
