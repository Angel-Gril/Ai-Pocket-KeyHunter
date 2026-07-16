import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CircleCheck,
  CircleX,
  Loader2,
  PlugZap,
  Power,
  Save,
  TriangleAlert,
} from "lucide-react"
import { toast } from "sonner"
import {
  ApiError,
  api,
  type FofaCheckResponse,
  type GithubCheckResponse,
  type SettingsUpdate,
  type SettingsView,
  type ShodanCheckResponse,
} from "@/lib/api"
import { Field } from "@/components/field"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

type FormState = Pick<
  SettingsView,
  | "fofa_keys"
  | "fofa_base_url"
  | "shodan_keys"
  | "shodan_base_url"
  | "github_tokens"
  | "github_api_base_url"
>

const FORM_FIELDS = [
  "fofa_keys",
  "fofa_base_url",
  "shodan_keys",
  "shodan_base_url",
  "github_tokens",
  "github_api_base_url",
] as const
const SENSITIVE = new Set<keyof FormState>(["fofa_keys", "shodan_keys", "github_tokens"])

function pickForm(view: SettingsView): FormState {
  return {
    fofa_keys: view.fofa_keys,
    fofa_base_url: view.fofa_base_url,
    shodan_keys: view.shodan_keys,
    shodan_base_url: view.shodan_base_url,
    github_tokens: view.github_tokens,
    github_api_base_url: view.github_api_base_url,
  }
}

function buildUpdate(form: FormState, baseline: FormState): SettingsUpdate {
  const update: SettingsUpdate = {}
  for (const field of FORM_FIELDS) {
    const value = form[field]
    if (value === baseline[field]) continue
    if (SENSITIVE.has(field) && value.includes("****")) continue
    update[field] = value
  }
  return update
}

const FOFA_STATE_META: Record<
  FofaCheckResponse["status"],
  { variant: "success" | "warning" | "danger"; box: string; icon: typeof CircleCheck; title: string }
> = {
  ok: { variant: "success", box: "bg-success-dim text-success", icon: CircleCheck, title: "可用" },
  quota_exhausted: {
    variant: "warning",
    box: "bg-warning-dim text-warning",
    icon: TriangleAlert,
    title: "配额已用完",
  },
  invalid: { variant: "danger", box: "bg-danger-dim text-danger", icon: CircleX, title: "无效" },
}

function resultShell(tone: string, children: React.ReactNode) {
  return (
    <div className={cn("flex items-start gap-2.5 rounded-sm px-3.5 py-2.5", tone)}>{children}</div>
  )
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "请求失败，请重试"
}

function FofaResult({
  isPending,
  data,
  error,
}: Readonly<{
  isPending: boolean
  data: FofaCheckResponse | undefined
  error: unknown
}>) {
  if (isPending) {
    return resultShell(
      "bg-surface-inset text-text-secondary",
      <>
        <Loader2 className="mt-px size-4 shrink-0 animate-spin" />
        <span className="font-mono text-xs">检测中…</span>
      </>,
    )
  }
  if (error) {
    return resultShell(
      "bg-danger-dim text-danger",
      <>
        <CircleX className="mt-px size-4 shrink-0" />
        <span className="font-mono text-xs">{errorMessage(error)}</span>
      </>,
    )
  }
  if (!data) return null
  const meta = FOFA_STATE_META[data.status]
  const Icon = meta.icon
  return resultShell(
    meta.box,
    <>
      <Icon className="mt-px size-4 shrink-0" />
      <div className="flex flex-col gap-0.5">
        <span className="font-mono text-[13px] font-semibold">{meta.title}</span>
        <span className="font-mono text-[11px] text-text-secondary">{data.message}</span>
      </div>
    </>,
  )
}

function ShodanResult({
  isPending,
  data,
  error,
}: Readonly<{
  isPending: boolean
  data: ShodanCheckResponse | undefined
  error: unknown
}>) {
  if (isPending) {
    return resultShell(
      "bg-surface-inset text-text-secondary",
      <>
        <Loader2 className="mt-px size-4 shrink-0 animate-spin" />
        <span className="font-mono text-xs">检测中…</span>
      </>,
    )
  }
  if (error) {
    return resultShell(
      "bg-danger-dim text-danger",
      <>
        <CircleX className="mt-px size-4 shrink-0" />
        <span className="font-mono text-xs">{errorMessage(error)}</span>
      </>,
    )
  }
  if (!data) return null
  const alive = data.n_keys - data.n_dead
  const allDead = data.n_keys > 0 && alive === 0
  return (
    <div className="flex flex-col gap-2">
      {resultShell(
        allDead ? "bg-danger-dim text-danger" : "bg-success-dim text-success",
        <>
          {allDead ? (
            <CircleX className="mt-px size-4 shrink-0" />
          ) : (
            <CircleCheck className="mt-px size-4 shrink-0" />
          )}
          <span className="font-mono text-[13px] font-semibold">
            {allDead ? "全部不可用" : `可用 · ${alive} 个 key 在线`}
          </span>
        </>,
      )}
      {data.keys.length > 0 ? (
        <div className="flex flex-col gap-1.5">
          <span className="font-mono text-[11px] text-text-muted">
            剩余查询配额 (query credits)
          </span>
          {data.keys.map((key) => (
            <div
              key={key.key_masked}
              className="flex items-center gap-3 rounded-sm bg-surface-inset px-3 py-2.5"
            >
              <span className="font-mono text-xs text-text-secondary">key {key.key_masked}</span>
              <span className="rounded-sm bg-surface-overlay px-1.5 py-0.5 font-mono text-[11px] text-text-muted">
                {key.plan || "unknown"}
              </span>
              <span
                className={cn(
                  "ml-auto font-mono text-sm font-semibold tabular-nums",
                  key.alive ? "text-success" : "text-danger",
                )}
              >
                {key.query_credits.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function SettingsForm({ initial }: Readonly<{ initial: SettingsView }>) {
  const queryClient = useQueryClient()
  const [baseline, setBaseline] = useState<FormState>(() => pickForm(initial))
  const [form, setForm] = useState<FormState>(() => pickForm(initial))

  const update = buildUpdate(form, baseline)
  const isDirty = Object.keys(update).length > 0

  const setField = (field: keyof FormState) => (event: React.ChangeEvent<HTMLInputElement>) => {
    const value = event.target.value
    setForm((prev) => ({ ...prev, [field]: value }))
  }

  const saveMutation = useMutation({
    mutationFn: () => api.updateSettings(update),
    onSuccess: (res) => {
      const next = pickForm(res.settings)
      setBaseline(next)
      setForm(next)
      queryClient.setQueryData(["settings"], res.settings)
      const restart = res.restart_required.length
      toast.success(
        restart > 0
          ? `已保存 ${res.updated.length} 项 · ${restart} 项需重启后端生效`
          : `已保存 ${res.updated.length} 项设置`,
      )
    },
    onError: (error) => toast.error(errorMessage(error)),
  })

  const fofaCheck = useMutation({ mutationFn: () => api.checkFofa() })
  const shodanCheck = useMutation({ mutationFn: () => api.checkShodan() })
  const githubCheck = useMutation({ mutationFn: () => api.checkGithub() })

  const restartMutation = useMutation({
    mutationFn: () => api.systemRestart(),
    onSuccess: () => toast.success("已发送重启指令，后端正在重启…"),
    onError: (error) => toast.error(errorMessage(error)),
  })

  const handleRestart = () => {
    const confirmed = window.confirm("确定要重启后端服务吗？重启期间接口将短暂不可用。")
    if (confirmed) restartMutation.mutate()
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-border-primary px-8 py-5">
        <div className="flex flex-1 flex-col gap-0.5">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">设置</h1>
          <p className="font-mono text-xs text-text-muted">数据源凭据 · 保存后热更新生效</p>
        </div>

        <Button
          variant="outline"
          onClick={handleRestart}
          disabled={restartMutation.isPending}
          className="border-border-primary bg-surface-overlay text-warning hover:bg-surface-overlay hover:text-warning dark:bg-surface-overlay dark:hover:bg-surface-overlay"
        >
          {restartMutation.isPending ? <Loader2 className="animate-spin" /> : <Power />}
          重启后端
        </Button>

        <Button onClick={() => saveMutation.mutate()} disabled={!isDirty || saveMutation.isPending}>
          {saveMutation.isPending ? <Loader2 className="animate-spin" /> : <Save />}
          保存
        </Button>
      </header>

      <div className="flex-1 overflow-y-auto px-8 py-6">
        <div className="flex flex-col gap-5">
          <section className="flex flex-col gap-[18px] rounded-md border border-border-primary bg-surface-raised p-6">
            <div className="flex items-center gap-2.5">
              <span className="size-2.5 rounded-full bg-info" />
              <h2 className="text-base font-semibold text-text-primary">FOFA</h2>
            </div>

            <Field
              label="FOFA_KEYS"
              htmlFor="fofa-keys"
              hint="逗号分隔多个 key · 运行时轮询 + 429/失败回退"
            >
              <Input
                id="fofa-keys"
                value={form.fofa_keys}
                onChange={setField("fofa_keys")}
                spellCheck={false}
                placeholder="key1,key2,key3"
                className="border-border-primary bg-surface-inset font-mono text-[13px] dark:bg-surface-inset"
              />
            </Field>

            <Field label="FOFA_BASE_URL" htmlFor="fofa-url">
              <Input
                id="fofa-url"
                value={form.fofa_base_url}
                onChange={setField("fofa_base_url")}
                spellCheck={false}
                className="border-border-primary bg-surface-inset font-mono text-[13px] dark:bg-surface-inset"
              />
            </Field>

            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => fofaCheck.mutate()}
                disabled={fofaCheck.isPending}
                className="border-border-primary bg-surface-overlay text-text-secondary hover:text-text-primary dark:bg-surface-overlay"
              >
                <PlugZap />
                检测可用性
              </Button>
              <span className="font-mono text-[11px] text-text-muted">探测消耗 1 次查询配额</span>
            </div>

            <FofaResult isPending={fofaCheck.isPending} data={fofaCheck.data} error={fofaCheck.error} />
          </section>

          <section className="flex flex-col gap-[18px] rounded-md border border-border-primary bg-surface-raised p-6">
            <div className="flex items-center gap-2.5">
              <span className="size-2.5 rounded-full bg-warning" />
              <h2 className="text-base font-semibold text-text-primary">Shodan</h2>
            </div>

            <Field
              label="SHODAN_KEYS"
              htmlFor="shodan-keys"
              hint="逗号分隔多个 key · 运行时轮询 + 429/失败回退"
            >
              <Input
                id="shodan-keys"
                value={form.shodan_keys}
                onChange={setField("shodan_keys")}
                spellCheck={false}
                placeholder="key1,key2,key3"
                className="border-border-primary bg-surface-inset font-mono text-[13px] dark:bg-surface-inset"
              />
            </Field>

            <Field label="SHODAN_BASE_URL" htmlFor="shodan-url">
              <Input
                id="shodan-url"
                value={form.shodan_base_url}
                onChange={setField("shodan_base_url")}
                spellCheck={false}
                className="border-border-primary bg-surface-inset font-mono text-[13px] dark:bg-surface-inset"
              />
            </Field>

            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => shodanCheck.mutate()}
                disabled={shodanCheck.isPending}
                className="border-border-primary bg-surface-overlay text-text-secondary hover:text-text-primary dark:bg-surface-overlay"
              >
                <PlugZap />
                检测 + 查配额
              </Button>
              <span className="font-mono text-[11px] text-text-muted">info 接口不消耗配额</span>
            </div>

            <ShodanResult
              isPending={shodanCheck.isPending}
              data={shodanCheck.data}
              error={shodanCheck.error}
            />
          </section>

          <section className="flex flex-col gap-[18px] rounded-md border border-border-primary bg-surface-raised p-6">
            <div className="flex items-center gap-2.5">
              <span className="size-2.5 rounded-full bg-success" />
              <h2 className="text-base font-semibold text-text-primary">GitHub</h2>
            </div>

            <Field
              label="GITHUB_TOKENS"
              htmlFor="github-tokens"
              hint="逗号分隔多个 PAT · 与 FOFA 相同：配额轮询 + 401 标记死钥 + 限流冷却回退"
            >
              <Input
                id="github-tokens"
                value={form.github_tokens}
                onChange={setField("github_tokens")}
                spellCheck={false}
                placeholder="ghp_xxx,github_pat_yyy"
                className="border-border-primary bg-surface-inset font-mono text-[13px] dark:bg-surface-inset"
              />
            </Field>

            <Field label="GITHUB_API_BASE_URL" htmlFor="github-url">
              <Input
                id="github-url"
                value={form.github_api_base_url}
                onChange={setField("github_api_base_url")}
                spellCheck={false}
                className="border-border-primary bg-surface-inset font-mono text-[13px] dark:bg-surface-inset"
              />
            </Field>

            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => githubCheck.mutate()}
                disabled={githubCheck.isPending}
                className="border-border-primary bg-surface-overlay text-text-secondary hover:text-text-primary dark:bg-surface-overlay"
              >
                <PlugZap />
                检测 rate_limit
              </Button>
              <span className="font-mono text-[11px] text-text-muted">
                /rate_limit 不消耗 search 配额 · 需 DATABASE_URL
              </span>
            </div>

            <GithubResult
              isPending={githubCheck.isPending}
              data={githubCheck.data}
              error={githubCheck.error}
            />
          </section>
        </div>
      </div>
    </div>
  )
}

function GithubResult({
  isPending,
  data,
  error,
}: Readonly<{
  isPending: boolean
  data: GithubCheckResponse | undefined
  error: unknown
}>) {
  if (isPending) {
    return resultShell(
      "bg-surface-inset text-text-secondary",
      <>
        <Loader2 className="mt-px size-4 shrink-0 animate-spin" />
        <span className="font-mono text-xs">检测中…</span>
      </>,
    )
  }
  if (error) {
    return resultShell(
      "bg-danger-dim text-danger",
      <>
        <CircleX className="mt-px size-4 shrink-0" />
        <span className="font-mono text-xs">{errorMessage(error)}</span>
      </>,
    )
  }
  if (!data) return null
  const ok = data.status === "ok"
  return resultShell(
    ok ? "bg-success-dim text-success" : "bg-danger-dim text-danger",
    <>
      {ok ? (
        <CircleCheck className="mt-px size-4 shrink-0" />
      ) : (
        <CircleX className="mt-px size-4 shrink-0" />
      )}
      <div className="flex flex-col gap-0.5">
        <span className="font-mono text-[13px] font-semibold">
          {ok ? "可用" : data.status === "disabled" ? "已禁用" : "不可用"}
        </span>
        <span className="font-mono text-[11px] text-text-secondary">
          {data.message}
          {ok
            ? ` · core=${data.core_remaining} search=${data.search_remaining} code=${data.code_search_remaining}`
            : ""}
        </span>
      </div>
    </>,
  )
}

export default function SettingsPage() {
  const { data, isPending, isError, error } = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.getSettings(),
  })

  if (isPending) {
    return (
      <div className="flex h-full items-center justify-center gap-2 text-text-muted">
        <Loader2 className="size-4 animate-spin" />
        <span className="font-mono text-sm">加载设置…</span>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-2 text-center">
        <span className="text-sm text-danger">加载失败</span>
        <span className="font-mono text-xs text-text-muted">
          {error instanceof Error ? error.message : "无法获取设置"}
        </span>
      </div>
    )
  }

  return <SettingsForm initial={data} />
}
