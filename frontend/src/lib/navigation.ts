export const NAV_ITEMS = [
  { to: "/history", label: "扫描历史" },
  { to: "/keys", label: "全部密钥" },
  { to: "/high-value", label: "高价值 Key" },
  { to: "/scan", label: "执行扫描" },
  { to: "/github", label: "GitHub 狩猎" },
  { to: "/manual", label: "自定义狩猎" },
  { to: "/cve", label: "CVE 库" },
  { to: "/honeypot", label: "蜜罐站点" },
  { to: "/settings", label: "设置" },
] as const

export type NavPath = (typeof NAV_ITEMS)[number]["to"]

export function navLabelForPath(pathname: string): string {
  if (pathname.startsWith("/runs/")) return "扫描结果"
  return NAV_ITEMS.find(({ to }) => pathname === to)?.label ?? "aipocket"
}
