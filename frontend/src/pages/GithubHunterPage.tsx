import { ScanConsole } from "@/pages/ScanPage"

/**
 * Dedicated GitHub artifact hunter console.
 *
 * Starts the same global scan singleton with source=github.
 * Validated keys flow through the identical writer → PG/history → AllKeys /
 * HighValue / RunResults path as FOFA/Shodan findings.
 */
export default function GithubHunterPage() {
  return (
    <ScanConsole
      fixedSource="github"
      title="GitHub 狩猎"
      startLabel="开始 GitHub 扫描"
      subtitle="source=github · 与全量扫描共用流水线 · 入库后在「扫描历史 / 全部密钥 / 高价值」统一展示"
    />
  )
}
