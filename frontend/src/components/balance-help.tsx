import { CircleHelp } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

function Section({ title, children }: Readonly<{ title: string; children: React.ReactNode }>) {
  return (
    <section className="space-y-1.5">
      <h3 className="font-mono text-[11px] font-semibold tracking-wide text-text-primary">{title}</h3>
      <div className="space-y-1 text-xs leading-relaxed text-text-secondary">{children}</div>
    </section>
  )
}

function Term({ name, children }: Readonly<{ name: string; children: React.ReactNode }>) {
  return (
    <p>
      <code className="rounded bg-surface-base px-1 py-0.5 font-mono text-[11px] text-accent">{name}</code>
      <span className="text-text-muted"> — </span>
      {children}
    </p>
  )
}

/** Compact “?” control that opens a glossary for BALANCE / tier labels. */
export function BalanceHelpButton() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <button
          type="button"
          aria-label="余额与等级说明"
          title="余额与等级说明"
          className="inline-flex size-4 shrink-0 items-center justify-center rounded-full border border-border-primary text-text-muted transition-colors hover:border-accent hover:text-accent"
        >
          <CircleHelp className="size-3" />
        </button>
      </DialogTrigger>
      <DialogContent className="max-h-[min(85dvh,640px)] overflow-y-auto border-border-primary bg-surface-raised sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-text-primary">余额 / 等级说明</DialogTitle>
          <DialogDescription className="text-text-muted">
            点击行上的「余额」按钮会实时探测。下列标签来自探测结果，不是每家厂商都有公开余额接口。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 pr-1">
          <Section title="BALANCE 列怎么读">
            <p>
              <strong className="text-text-primary">第一行数字</strong>
              （如 <code className="font-mono text-[11px]">$14.50</code>
              ）= 查到的剩余额度（美元）。
            </p>
            <p>
              <strong className="text-text-primary">N/A</strong> = 当前 key
              无法通过 API 读到「剩余余额」（接口不存在、需网页 Session、或权限不足）。Key 仍可能可用。
            </p>
            <p>
              <strong className="text-text-primary">第二行灰色小字</strong> = 使用层级 / 限流画像（tier），用于判断账号档位。
            </p>
          </Section>

          <Section title="OpenAI">
            <Term name="api:payg">
              按量付费普通 API key。key 存活，但拿不到真余额，也没有 rate-limit 头可推断 Tier 1–5。
              <strong className="text-text-primary"> 不是</strong> 控制台里的官方 Usage Tier 名称。
            </Term>
            <Term name="tier1 … tier5 / tier5_candidate">
              与 OpenAI Usage Tier 相关。带{" "}
              <code className="font-mono text-[11px]">_candidate</code>{" "}
              的是根据 RPM/TPM 或 soft hard_limit
              <strong className="text-text-primary"> 推测</strong>；Admin key 读到的{" "}
              <code className="font-mono text-[11px]">account_tier</code> 更可信。
            </Term>
            <Term name="rpm:… / tpm:…">从响应头读到的每分钟请求/Token 上限，不是账户名。</Term>
            <Term name="unknown">扫描阶段未拿到限流证据时的占位；点「余额」后应被新标签覆盖。</Term>
            <p className="pt-0.5 text-text-muted">
              官方 Usage Tier：Free → Tier1($5 付费) → … → Tier5($1000 付费)。真余额多依赖
              dashboard/billing（部分账号仅 Session Token 可查）。
            </p>
          </Section>

          <Section title="Anthropic (Claude)">
            <Term name="api:payg / api:usage_tier_*">
              普通 <code className="font-mono text-[11px]">sk-ant-api…</code>{" "}
              没有公开 remaining-balance 接口，余额固定 N/A。后缀 frontier/standard
              表示模型列表里是否含 Opus/Sonnet 等。
            </Term>
            <Term name="usage_tier:start / build / scale">
              根据 Admin Rate Limits（或响应头 RPM/ITPM）对照官方档位表的推断：Start → Build → Scale。
            </Term>
            <Term name="org:admin">Admin key 能读组织信息，但尚未映射到 Start/Build/Scale。</Term>
            <p className="pt-0.5 text-text-muted">
              近 30 天花费仅 Admin key（
              <code className="font-mono text-[11px]">sk-ant-admin…</code>
              ）可通过 Cost Report 获取，且是「已花费」不是「剩余余额」。
            </p>
          </Section>

          <Section title="其他常见网关">
            <Term name="$ 数字">OpenRouter / NewAPI / LiteLLM / DeepSeek 等能直接返回的剩余额度。</Term>
            <Term name="gateway · unsupported">所有已知探针均未命中，未识别平台或 key 无效。</Term>
          </Section>

          <Section title="操作提示">
            <p>点「余额」只做只读探测（billing / models / admin 接口），一般不消耗对话额度。</p>
            <p>点「测对话」会真实发起 completion，可能扣费。</p>
          </Section>
        </div>
      </DialogContent>
    </Dialog>
  )
}
