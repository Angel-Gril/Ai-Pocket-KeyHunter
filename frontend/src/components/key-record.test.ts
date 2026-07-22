import { describe, expect, it } from "vitest"
import { extractKeyFields } from "@/components/key-record"
import { providerBrand } from "@/components/provider-badge"
import type { KeyRecord } from "@/lib/api"

function record(overrides: Partial<KeyRecord> = {}): KeyRecord {
  return {
    credential: {
      apikey: "sk-…masked",
      apiurl: "https://api.example/v1",
      source: "",
      source_type: "fingerprint",
      backend: "fofa",
      host: "https://api.example",
      ip: "",
      port: "",
      product: "",
      raw_context: "",
      leak_host: "",
      routed_to_official: false,
    },
    valid: true,
    status_code: 200,
    error: "",
    tier: "",
    gateway: "",
    balance: "",
    rate_limit_headers: {},
    model_available: "",
    response_snippet: "",
    provider_info: {
      provider: "newapi",
      category: "gateway",
      models_available: [],
      models_verified: [],
      balance_provider: "",
    },
    validated_at: "2026-07-01T00:00:00Z",
    suspicious: false,
    suspicious_reason: "",
    ...overrides,
  }
}

describe("key display fields", () => {
  it("uses results.created_at over validation approximation", () => {
    expect(extractKeyFields(record({ created_at: "2026-07-22T01:02:03Z" })).createdAt).toBe(
      "2026-07-22T01:02:03Z",
    )
  })

  it("extracts high-value saved_at independently", () => {
    expect(extractKeyFields(record({ saved_at: "2026-07-22T02:00:00Z" })).savedAt).toBe(
      "2026-07-22T02:00:00Z",
    )
  })

  it("keeps provider evidence when cash balance is unavailable", () => {
    const fields = extractKeyFields(
      record({
        provider_evidence: {
          provider: "ksyun",
          source: "ksyun:models",
          evidence_kind: "entitlement",
          entitlements: { models: ["deepseek-v3"] },
        },
      }),
    )
    expect(fields.balance).toBeUndefined()
    expect(fields.evidence?.entitlements).toEqual({ models: ["deepseek-v3"] })
  })

  it.each(["minimax", "nvidia", "ksyun", "longcat", "newapi", "oneapi", "litellm"])(
    "has an explicit badge for %s",
    (provider) => expect(providerBrand(provider).label).not.toBe(provider),
  )
})
