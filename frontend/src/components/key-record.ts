import type { KeyRecord } from "@/lib/api"
import type { KeyRowStatus } from "@/components/key-row"

export interface KeyFields {
  maskedKey: string
  apiurl?: string
  host?: string
  provider?: string
  balance?: string
  tier?: string
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

/** Normalise a balance string into a `$`-prefixed amount when it looks numeric. */
export function formatBalance(raw?: string): string | undefined {
  if (!raw) return undefined
  if (raw.startsWith("$")) return raw
  if (/^-?\d/.test(raw)) return `$${raw}`
  return raw
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
  }
}

export function deriveKeyStatus(rec: KeyRecord): KeyRowStatus {
  if (rec.suspicious) return { variant: "warning", label: "疑似" }
  if (rec.valid) return { variant: "success", label: "有效" }
  const code = rec.status_code
  if (typeof code === "number") return { variant: "danger", label: String(code) }
  return { variant: "muted", label: "无效" }
}

export function providerOf(rec: KeyRecord): string {
  return extractKeyFields(rec).provider ?? "unknown"
}
