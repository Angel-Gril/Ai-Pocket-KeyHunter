import { Navigate, Route, Routes } from "react-router-dom"
import { AppLayout } from "@/components/app-layout"
import { ProtectedRoute } from "@/components/protected-route"
import LoginPage from "@/pages/LoginPage"
import HistoryPage from "@/pages/HistoryPage"
import RunResultsPage from "@/pages/RunResultsPage"
import AllKeysPage from "@/pages/AllKeysPage"
import HighValuePage from "@/pages/HighValuePage"
import ScanPage from "@/pages/ScanPage"
import GithubHunterPage from "@/pages/GithubHunterPage"
import CvePage from "@/pages/CvePage"
import HoneypotPage from "@/pages/HoneypotPage"
import SettingsPage from "@/pages/SettingsPage"

export function App() {
  return (
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
          <Route path="/cve" element={<CvePage />} />
          <Route path="/honeypot" element={<HoneypotPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/history" replace />} />
    </Routes>
  )
}
