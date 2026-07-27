import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"
import {
  evidenceObservedLabel,
  formatEvidenceRecord,
  KeyRow,
} from "@/components/key-row"

const evidence = {
  provider: "fireworks",
  source: "fireworks:accounts_quotas",
  evidence_kind: "quota" as const,
  account_type: "STANDARD",
  quota: { name: "monthly-spend-usd", maxValue: 500, usage: 12, unit: "USD" },
  usage: { window: "monthly", value: 12 },
  identity: { account_id: "accounts/very-sensitive-id", email: "owner@example.com" },
  detail: { cash_balance_state: "depleted" },
  observed_at: "2026-07-22T00:00:00Z",
}

describe("provider evidence presentation", () => {
  it("formats missing and masked evidence without inventing values", () => {
    expect(formatEvidenceRecord(undefined)).toBe("N/A")
    expect(formatEvidenceRecord({})).toBe("N/A")
    expect(formatEvidenceRecord({ account_id: "accounts/very-sensitive-id" }, true)).toBe(
      '{"account_id":"acco…e-id"}',
    )
    expect(formatEvidenceRecord({ maxValue: 500, usage: 12 })).toContain('"maxValue":500')
    expect(formatEvidenceRecord({ account_id: "short" }, true)).toBe('{"account_id":"short"}')
  })

  it("labels valid, invalid, and missing observation timestamps", () => {
    expect(evidenceObservedLabel()).toBe("上次探测：N/A")
    expect(evidenceObservedLabel("not-a-date")).toBe("上次探测：not-a-date")
    expect(evidenceObservedLabel("2026-07-22T00:00:00Z")).toContain("上次探测：")
  })

  it("shows quota, usage, masked identity, stale marker, and depleted state", () => {
    render(
      <KeyRow
        maskedKey="sk-…masked"
        apiurl="https://api.fireworks.ai/inference/v1"
        host="https://api.fireworks.ai"
        provider="fireworks"
        expanded
        evidence={evidence}
      />,
    )
    expect(screen.getByText("配额 / 剩余额度")).toBeInTheDocument()
    expect(screen.getByText("用量 / 窗口")).toBeInTheDocument()
    expect(screen.getByText('{"window":"monthly","value":12}')).toBeInTheDocument()
    expect(screen.getByText('{"account_id":"acco…e-id","email":"owne….com"}')).toBeInTheDocument()
    expect(screen.getByText("现金余额状态：已耗尽（无数值余额）")).toBeInTheDocument()
  })


  it("exposes all manual status transition actions", async () => {
    const user = userEvent.setup()
    const onMarkValid = vi.fn()
    const onMarkSuspicious = vi.fn()
    const onMarkUnavailable = vi.fn()
    render(
      <KeyRow
        maskedKey="sk-…masked"
        onMarkValid={onMarkValid}
        onMarkSuspicious={onMarkSuspicious}
        onMarkUnavailable={onMarkUnavailable}
      />,
    )
    await user.click(screen.getByRole("button", { name: "标为可用" }))
    await user.click(screen.getByRole("button", { name: "标为疑似" }))
    await user.click(screen.getByRole("button", { name: "标为不可用" }))
    expect(onMarkValid).toHaveBeenCalledOnce()
    expect(onMarkSuspicious).toHaveBeenCalledOnce()
    expect(onMarkUnavailable).toHaveBeenCalledOnce()
  })
})


it("loads and collapses model details through the row toggle", async () => {
  const user = userEvent.setup()
  const onLoadModels = vi.fn()
  const onExpandedChange = vi.fn()
  const { rerender } = render(
    <KeyRow
      maskedKey="sk-…masked"
      onLoadModels={onLoadModels}
      onExpandedChange={onExpandedChange}
    />,
  )
  expect(screen.queryByText("gpt-4o")).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Expand models" }))
  expect(onLoadModels).toHaveBeenCalledOnce()
  expect(onExpandedChange).toHaveBeenCalledWith(true)
  rerender(
    <KeyRow
      maskedKey="sk-…masked"
      models={["gpt-4o"]}
      modelsLoading
      expanded
      onExpandedChange={onExpandedChange}
    />,
  )
  expect(screen.getByText("gpt-4o")).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Collapse models" }))
  expect(onExpandedChange).toHaveBeenCalledWith(false)
})


it("forwards selection and action callbacks", async () => {
  const user = userEvent.setup()
  const onSelectedChange = vi.fn()
  const onReveal = vi.fn()
  const onCopy = vi.fn()
  const onLoadModels = vi.fn()
  const onBalance = vi.fn()
  const onChat = vi.fn()
  render(
    <KeyRow
      maskedKey="sk-…masked"
      onSelectedChange={onSelectedChange}
      onReveal={onReveal}
      onCopy={onCopy}
      onLoadModels={onLoadModels}
      onBalance={onBalance}
      onChat={onChat}
      busy={{ models: true, balance: true, chat: true }}
    />,
  )
  await user.click(screen.getByRole("checkbox", { name: "Select key" }))
  await user.click(screen.getByRole("button", { name: "Reveal key" }))
  await user.click(screen.getByRole("button", { name: "Copy key" }))
  expect(onSelectedChange).toHaveBeenCalledWith(true)
  expect(onReveal).toHaveBeenCalledOnce()
  expect(onCopy).toHaveBeenCalledOnce()
  expect(screen.getByRole("button", { name: "模型列表" })).toBeDisabled()
  expect(screen.getByRole("button", { name: "余额" })).toBeDisabled()
  expect(screen.getByRole("button", { name: "测对话" })).toBeDisabled()
})
