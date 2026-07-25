import { useState } from "react"
import { Navigate, useNavigate } from "react-router-dom"
import { useMutation } from "@tanstack/react-query"
import { ArrowRight, Eye, EyeOff, Loader2, LockKeyhole, Shield } from "lucide-react"
import { toast } from "sonner"
import { ApiError } from "@/lib/api"
import { useAuth } from "@/providers/auth-provider"
import { Field } from "@/components/field"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export default function LoginPage() {
  const { isAuthenticated, login } = useAuth()
  const navigate = useNavigate()
  const [password, setPassword] = useState("")
  const [reveal, setReveal] = useState(false)

  const mutation = useMutation({
    mutationFn: (value: string) => login(value),
    onSuccess: () => navigate("/history", { replace: true }),
    onError: (error) => {
      const message = error instanceof ApiError ? error.message : "登录失败，请重试"
      toast.error(message)
    },
  })

  if (isAuthenticated) return <Navigate to="/history" replace />

  const submit = () => {
    const value = password.trim()
    if (value.length === 0) {
      toast.error("请输入访问密码")
      return
    }
    mutation.mutate(value)
  }

  return (
    <div className="flex min-h-dvh items-center justify-center bg-surface-base p-4 sm:p-6">
      <form
        onSubmit={(event) => {
          event.preventDefault()
          submit()
        }}
        className="flex w-full max-w-[400px] flex-col gap-6 rounded-md border border-border-primary bg-surface-raised p-5 sm:p-9"
      >
        <div className="flex items-center gap-2.5">
          <span className="size-3 rounded-full bg-accent" />
          <span className="font-mono text-[22px] font-semibold tracking-[-0.3px] text-text-primary">
            aipocket
          </span>
        </div>

        <div className="flex flex-col gap-1.5">
          <h1 className="text-[15px] font-semibold text-text-primary">访问验证</h1>
          <p className="text-[13px] leading-relaxed text-text-secondary">
            该控制台可导出明文密钥并触发扫描，请输入全局访问密码。
          </p>
        </div>

        <Field label="访问密码" htmlFor="login-password">
          <div className="relative flex items-center">
            <LockKeyhole className="pointer-events-none absolute left-3.5 size-[15px] text-text-muted" />
            <Input
              id="login-password"
              type={reveal ? "text" : "password"}
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={mutation.isPending}
              placeholder="••••••••••••"
              className="border-border-primary bg-surface-inset px-10 font-mono text-sm dark:bg-surface-inset"
            />
            <button
              type="button"
              onClick={() => setReveal((prev) => !prev)}
              aria-label={reveal ? "隐藏密码" : "显示密码"}
              className="absolute right-3.5 text-text-muted transition-colors hover:text-text-secondary"
            >
              {reveal ? <EyeOff className="size-[15px]" /> : <Eye className="size-[15px]" />}
            </button>
          </div>
        </Field>

        <Button type="submit" className="w-full" disabled={mutation.isPending}>
          {mutation.isPending ? (
            <>
              <Loader2 className="animate-spin" />
              验证中…
            </>
          ) : (
            <>
              <ArrowRight />
              进入控制台
            </>
          )}
        </Button>

        <div className="flex items-center justify-center gap-1.5 text-text-muted">
          <Shield className="size-[13px]" />
          <span className="font-mono text-[11px]">请通过 HTTPS 访问 · 密码不会被记录</span>
        </div>
      </form>
    </div>
  )
}
