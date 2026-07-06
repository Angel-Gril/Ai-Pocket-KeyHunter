import { Navigate, Outlet, useLocation } from "react-router-dom"
import { useAuth } from "@/providers/auth-provider"

export function ProtectedRoute() {
  const { isAuthenticated } = useAuth()
  const location = useLocation()

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return <Outlet />
}
