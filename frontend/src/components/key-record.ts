import type { KeyRecord } from "@/lib/api"
import type { KeyRowStatus } from "@/components/key-row"

export interface KeyFields {
  maskedKey: string
  apiurl?: string
  host?: string
  provider?: string
  balance?: string
  tier?: string
  credentialKind?: string
  validationState?: string
  scope?: string
  tierEvidence?: string
  createdAt?: string
  savedAt?: string
  evidence?: KeyRecord["provider_evidence"]
}

function text(value: unknown): string | undefined {
  if (typeof value === "number" || typeof value === "boolean") return String(value)
  if (typeof value !== "string") return undefined
  const trimmed = value.trim()
  if (!trimmed || trimmed === "—") return undefined
  return trimmed
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {}
}

/**
 * Normalise a balance string for display.
 * - Keep existing currency markers (`$`, `¥`/`￥`, `CNY`, `USD`, `元`, …)
 * - Bare numbers default to `$` (USD) — backend writes `¥…` for CNY native cash
 */
export function formatBalance(raw?: string): string | undefined {
  if (!raw) return undefined
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  // Already labelled — do not force `$` onto CNY / other units.
  // Note: avoid `\b` around CJK (元/人民币); word-boundary is ASCII-oriented.
  if (/[\$¥￥]|cny|usd|rmb|元|人民币|美元/i.test(trimmed)) return trimmed
  if (/^-?\d/.test(trimmed)) return `$${trimmed}`
  return trimmed
}

const STATE_LABELS: Record<string, { variant: KeyRowStatus["variant"]; label: string }> = {
  final_verified: { variant: "success", label: "最终可用" },
  authentication_confirmed: { variant: "success", label: "已认证" },
  scope_confirmed: { variant: "success", label: "范围确认" },
  inference_verified: { variant: "success", label: "推理确认" },
  no_auth_disproved: { variant: "success", label: "已复核" },
  rate_limited_unconfirmed: { variant: "warning", label: "限流待确认" },
  auth_rejected: { variant: "danger", label: "认证失败" },
  no_auth_endpoint: { variant: "danger", label: "无鉴权" },
  provider_conflict: { variant: "warning", label: "Provider冲突" },
  unsupported_context: { variant: "warning", label: "上下文不足" },
  transient_error: { variant: "warning", label: "瞬时错误" },
  scope_unverified: { variant: "warning", label: "范围未确认" },
  structurally_valid: { variant: "muted", label: "结构有效" },
  discovered: { variant: "muted", label: "已发现" },
}

/** Pull display fields from a record that may be nested (run results) or flat (high-value). */
export function extractKeyFields(rec: KeyRecord): KeyFields {
  const cred = asRecord(rec.credential)
  const provider = asRecord(rec.provider_info)
  return {
    maskedKey: text(cred.apikey) ?? text(rec.apikey) ?? "—",
    apiurl: text(cred.apiurl) ?? text(rec.apiurl),
    host: text(cred.host) ?? text(rec.host),
    provider: text(provider.provider) ?? text(rec.provider),
    balance: formatBalance(text(rec.balance)),
    tier: text(rec.tier),
    credentialKind: text(rec.credential_kind),
    validationState: text(rec.validation_state),
    scope: text(rec.scope),
    tierEvidence: text(rec.tier_evidence) ?? text(rec.tier),
    createdAt: text(rec.created_at) ?? text(rec.validated_at),
    savedAt: text(rec.saved_at),
    evidence: rec.provider_evidence,
  }
}

export function deriveKeyStatus(rec: KeyRecord): KeyRowStatus {
  if (rec.manual_status === "valid") {
    return { variant: "success", label: "可用" }
  }
  if (rec.manual_status === "suspicious") {
    return { variant: "warning", label: "疑似" }
  }
  if (rec.manual_status === "unavailable") {
    return { variant: "danger", label: "不可用" }
  }
  if (rec.suspicious || rec.validation_state === "rate_limited_unconfirmed") {
    return { variant: "warning", label: "疑似" }
  }
  const state = text(rec.validation_state)
  if (state && STATE_LABELS[state]) return STATE_LABELS[state]
  if (rec.valid) return { variant: "success", label: "有效" }
  const code = rec.status_code
  if (typeof code === "number") return { variant: "danger", label: String(code) }
  return { variant: "muted", label: "无效" }
}

export function providerOf(rec: KeyRecord): string {
  return extractKeyFields(rec).provider ?? "unknown"
}
