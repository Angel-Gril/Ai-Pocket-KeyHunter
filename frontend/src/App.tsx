import { lazy, Suspense } from "react"
import { Navigate, Route, Routes } from "react-router-dom"
import { AppLayout } from "@/components/app-layout"
import { ProtectedRoute } from "@/components/protected-route"

const LoginPage = lazy(() => import("@/pages/LoginPage"))
const HistoryPage = lazy(() => import("@/pages/HistoryPage"))
const RunResultsPage = lazy(() => import("@/pages/RunResultsPage"))
const AllKeysPage = lazy(() => import("@/pages/AllKeysPage"))
const HighValuePage = lazy(() => import("@/pages/HighValuePage"))
const ScanPage = lazy(() => import("@/pages/ScanPage"))
const GithubHunterPage = lazy(() => import("@/pages/GithubHunterPage"))
const ManualTargetsPage = lazy(() => import("@/pages/ManualTargetsPage"))
const CvePage = lazy(() => import("@/pages/CvePage"))
const HoneypotPage = lazy(() => import("@/pages/HoneypotPage"))
const SettingsPage = lazy(() => import("@/pages/SettingsPage"))

const routeFallback = (
  <div className="flex h-full min-h-48 items-center justify-center font-mono text-sm text-text-muted">
    页面加载中…
  </div>
)

export function App() {
  return (
    <Suspense fallback={routeFallback}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route index element={<Navigate to="/history" replace />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/runs/:runId" element={<RunResultsPage />} />
            <Route path="/keys" element={<AllKeysPage />} />
            <Route path="/high-value" element={<HighValuePage />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/github" element={<GithubHunterPage />} />
            <Route path="/manual" element={<ManualTargetsPage />} />
            <Route path="/cve" element={<CvePage />} />
            <Route path="/honeypot" element={<HoneypotPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/history" replace />} />
      </Routes>
    </Suspense>
  )
}
