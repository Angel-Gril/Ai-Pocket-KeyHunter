import { useId } from "react"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"

export interface FieldProps {
  label: string
  htmlFor?: string
  hint?: string
  className?: string
  children: React.ReactNode
}

/**
 * Labeled form field (pencil `component/Field`): a mono label above the control
 * (typically an `Input` or `Select`), with an optional hint line beneath.
 * When `htmlFor` is omitted a generated id is applied to the child control.
 */
export function Field({ label, htmlFor, hint, className, children }: FieldProps) {
  const generatedId = useId()
  const controlId = htmlFor ?? generatedId

  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={controlId} className="font-mono text-xs font-normal text-text-secondary">
        {label}
      </Label>
      {children}
      {hint ? <p className="font-mono text-[11px] text-text-muted">{hint}</p> : null}
    </div>
  )
}
