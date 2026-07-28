import { describe, expect, it } from "vitest"
import { extractKeyFields } from "@/components/key-record"
import { providerBrand } from "@/components/provider-badge"
import { applyBatchBalanceResults } from "@/lib/batch-balance"
import type { BatchBalanceResponse, KeyRecord } from "@/lib/api"

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

describe("batch balance display updates", () => {
  it("applies successful returned balances by result_id and leaves failures unchanged", () => {
    const records = [
      record({ result_id: 11, balance: "1", tier: "old", gateway: "old" }),
      record({ result_id: 12, balance: "2", tier: "kept", gateway: "kept" }),
    ]
    const report: BatchBalanceResponse = {
      requested: 2,
      succeeded: 1,
      failed: 1,
      results: [
        {
          result_id: 11,
          ok: true,
          balance: {
            gateway: "openrouter",
            balance_usd: "37.5",
            tier: "paid",
            detail: { source: "openrouter:credits", evidence_kind: "cash_balance" },
            persisted: true,
          },
        },
        { result_id: 12, ok: false, error: "probe failed" },
      ],
    }

    const updated = applyBatchBalanceResults(records, report)

    expect(extractKeyFields(updated[0]).balance).toBe("$37.5")
    expect(updated[0]).toMatchObject({ tier: "paid", gateway: "openrouter" })
    expect(updated[0].provider_evidence).toMatchObject({ source: "openrouter:credits" })
    expect(updated[1]).toBe(records[1])
  })
})
