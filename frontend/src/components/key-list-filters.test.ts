import { describe, expect, it } from "vitest"
import {
  balanceSortValue,
  CNY_TO_USD_SORT_RATE,
  parseBalance,
  parseBalanceNumber,
} from "@/components/key-list-filters"
import { formatBalance } from "@/components/key-record"

describe("parseBalance", () => {
  it("parses USD forms", () => {
    expect(parseBalance("$17.48")).toEqual({ amount: 17.48, currency: "USD" })
    expect(parseBalance("9.59")).toEqual({ amount: 9.59, currency: "USD" })
    expect(parseBalance("$1,234.50")).toEqual({ amount: 1234.5, currency: "USD" })
    expect(parseBalance("USD 6.25")).toEqual({ amount: 6.25, currency: "USD" })
  })

  it("parses CNY forms (must not be treated as unsortable)", () => {
    expect(parseBalance("¥110")).toEqual({ amount: 110, currency: "CNY" })
    expect(parseBalance("￥6.5")).toEqual({ amount: 6.5, currency: "CNY" })
    expect(parseBalance("110 CNY")).toEqual({ amount: 110, currency: "CNY" })
    expect(parseBalance("CNY 110.0")).toEqual({ amount: 110, currency: "CNY" })
    expect(parseBalance("100 元")).toEqual({ amount: 100, currency: "CNY" })
  })

  it("returns null for non-cash labels", () => {
    expect(parseBalance("N/A")).toBeNull()
    expect(parseBalance("unknown")).toBeNull()
    expect(parseBalance("—")).toBeNull()
    expect(parseBalance("")).toBeNull()
    expect(parseBalance(undefined)).toBeNull()
  })
})

describe("balanceSortValue (multi-currency ranking)", () => {
  it("ranks pure USD high-to-low by numeric amount", () => {
    const rows = ["$6.25", "$17.48", "$9.59", "N/A", "$8.96"]
    const sorted = [...rows].sort((a, b) => {
      const na = balanceSortValue(a)
      const nb = balanceSortValue(b)
      if (na === null && nb === null) return 0
      if (na === null) return 1
      if (nb === null) return -1
      return nb - na
    })
    expect(sorted).toEqual(["$17.48", "$9.59", "$8.96", "$6.25", "N/A"])
  })

  it("converts CNY with fixed rate so ¥ and $ are comparable", () => {
    // ¥72 ≈ $10 at rate 7.2; should rank below $17 and above $6
    const cnySort = balanceSortValue("¥72")
    expect(cnySort).toBeCloseTo(72 / CNY_TO_USD_SORT_RATE, 6)
    expect(cnySort).toBeCloseTo(10, 6)

    const rows = ["$6.25", "¥72", "$17.48", "¥7.2"]
    const sorted = [...rows].sort(
      (a, b) => (balanceSortValue(b) ?? -Infinity) - (balanceSortValue(a) ?? -Infinity),
    )
    // $17.48 > ¥72(~$10) > $6.25 > ¥7.2(~$1)
    expect(sorted).toEqual(["$17.48", "¥72", "$6.25", "¥7.2"])
  })

  it("does not sink CNY below N/A (old bug: ¥ parsed as null)", () => {
    expect(parseBalanceNumber("¥110")).not.toBeNull()
    expect(parseBalanceNumber("¥110")).toBeCloseTo(110 / CNY_TO_USD_SORT_RATE, 6)
  })
})

describe("formatBalance", () => {
  it("prefixes bare numbers with $", () => {
    expect(formatBalance("17.48")).toBe("$17.48")
  })

  it("preserves CNY markers (must not force $)", () => {
    expect(formatBalance("¥110")).toBe("¥110")
    expect(formatBalance("￥6.5")).toBe("￥6.5")
    expect(formatBalance("110 CNY")).toBe("110 CNY")
    expect(formatBalance("100 元")).toBe("100 元")
  })

  it("preserves existing $", () => {
    expect(formatBalance("$9.59")).toBe("$9.59")
  })
})
