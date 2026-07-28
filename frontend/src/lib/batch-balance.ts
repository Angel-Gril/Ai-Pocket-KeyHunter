import type { BatchBalanceResponse, KeyRecord } from "@/lib/api"

export function applyBatchBalanceResults(
  records: KeyRecord[],
  report: BatchBalanceResponse,
): KeyRecord[] {
  const successful = new Map(
    report.results.flatMap((item) => item.ok && item.balance
      ? [[item.result_id, item.balance] as const]
      : []),
  )
  if (successful.size === 0) return records
  return records.map((record) => {
    const resultId = record.result_id
    const balance = resultId == null ? undefined : successful.get(resultId)
    if (!balance) return record
    return {
      ...record,
      balance: balance.balance_usd,
      tier: balance.tier || record.tier,
      gateway: balance.gateway || record.gateway,
      provider_evidence:
        (balance.detail as KeyRecord["provider_evidence"]) ?? record.provider_evidence,
    }
  })
}
