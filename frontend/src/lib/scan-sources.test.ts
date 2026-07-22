import { describe, expect, it } from "vitest"
import {
  ALL_SCAN_SOURCES,
  parseSourceLabel,
  serializeSources,
  toCanonicalSourceLabel,
  toggleAllSources,
  toggleSource,
} from "@/lib/scan-sources"

describe("scan source selection", () => {
  it("selects all on first all-toggle and clears on second", () => {
    expect(toggleAllSources(["fofa"])).toEqual(ALL_SCAN_SOURCES)
    expect(toggleAllSources(ALL_SCAN_SOURCES)).toEqual([])
  })

  it("toggles individual sources and allows an empty selection", () => {
    expect(toggleSource(["fofa"], "fofa")).toEqual([])
    expect(toggleSource(["fofa"], "github")).toEqual(["fofa", "github"])
  })

  it("canonicalizes empty, full, single, and partial selections", () => {
    expect(serializeSources([])).toBeNull()
    expect(toCanonicalSourceLabel([])).toBe("")
    expect(toCanonicalSourceLabel(ALL_SCAN_SOURCES)).toBe("all")
    expect(toCanonicalSourceLabel(["shodan"])).toBe("shodan")
    expect(toCanonicalSourceLabel(["shodan", "fofa"])).toBe("fofa,shodan")
  })

  it("serializes only a true full selection as all", () => {
    expect(serializeSources(ALL_SCAN_SOURCES)).toEqual({ source: "all", sources: [] })
    expect(serializeSources(["fofa", "shodan"])).toEqual({
      source: "fofa",
      sources: ["fofa", "shodan"],
    })
    expect(serializeSources(["github"])).toEqual({ source: "github", sources: ["github"] })
  })

  it("parses canonical labels without inventing sources", () => {
    expect(parseSourceLabel("fofa,github")).toEqual(["fofa", "github"])
    expect(parseSourceLabel("invalid")).toEqual([])
    expect(parseSourceLabel(undefined)).toEqual(ALL_SCAN_SOURCES)
    expect(parseSourceLabel("all")).toEqual(ALL_SCAN_SOURCES)
    expect(parseSourceLabel(" fofa , invalid , shodan ")).toEqual(["fofa", "shodan"])
  })
})
