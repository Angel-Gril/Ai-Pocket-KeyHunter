import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react"
import { api, setUnauthorizedHandler } from "@/lib/api"
import { clearToken, getToken, setToken } from "@/lib/auth-storage"

interface AuthContextValue {
  token: string | null
  isAuthenticated: boolean
  login: (password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(() => getToken())

  useEffect(() => {
    setUnauthorizedHandler(() => setTokenState(null))
    return () => setUnauthorizedHandler(null)
  }, [])

  const login = useCallback(async (password: string) => {
    const res = await api.login(password)
    setToken(res.token)
    setTokenState(res.token)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      /* best-effort — the token is stateless, so local cleanup is enough */
    }
    clearToken()
    setTokenState(null)
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({ token, isAuthenticated: token !== null, login, logout }),
    [token, login, logout],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (ctx === null) throw new Error("useAuth must be used within an AuthProvider")
  return ctx
}
