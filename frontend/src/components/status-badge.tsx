import { cn } from "@/lib/utils"

export type StatusVariant = "success" | "danger" | "warning" | "info" | "muted"

const VARIANT_STYLES: Record<StatusVariant, { container: string; dot: string }> = {
  success: { container: "bg-success-dim text-success", dot: "bg-success" },
  danger: { container: "bg-danger-dim text-danger", dot: "bg-danger" },
  warning: { container: "bg-warning-dim text-warning", dot: "bg-warning" },
  info: { container: "bg-info-dim text-info", dot: "bg-info" },
  muted: { container: "bg-surface-overlay text-text-secondary", dot: "bg-text-muted" },
}

export interface StatusBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: StatusVariant
  label: string
  showDot?: boolean
}

export function StatusBadge({
  variant = "muted",
  label,
  showDot = true,
  className,
  ...props
}: StatusBadgeProps) {
  const styles = VARIANT_STYLES[variant]
  return (
    <span
      className={cn(
        // w-fit: never stretch when a parent flex column defaults to items-stretch
        // (e.g. STATUS cell after the column is resized wider than the label).
        "inline-flex w-fit max-w-full shrink-0 items-center gap-1.5 rounded-sm px-[9px] py-1 font-mono text-xs font-medium",
        styles.container,
        className,
      )}
      {...props}
    >
      {showDot ? <span className={cn("size-[7px] shrink-0 rounded-full", styles.dot)} /> : null}
      {label}
    </span>
  )
}
