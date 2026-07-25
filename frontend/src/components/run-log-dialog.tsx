import { Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

interface RunLogDialogProps {
  runId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  log?: string
  loading?: boolean
  error?: unknown
}

export function RunLogDialog({
  runId,
  open,
  onOpenChange,
  log,
  loading = false,
  error,
}: Readonly<RunLogDialogProps>) {
  const message = error instanceof Error ? error.message : "无法读取运行日志"

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[min(85dvh,760px)] flex-col gap-4 border-border-primary bg-surface-raised sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="pr-6 text-text-primary">运行日志</DialogTitle>
          <DialogDescription className="font-mono text-xs break-all text-text-muted">
            {runId}
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-[280px] flex-1 overflow-auto rounded-md border border-border-primary bg-surface-inset p-4 sm:min-h-[420px]">
          {loading ? (
            <div className="flex h-full items-center justify-center gap-2 text-text-muted">
              <Loader2 className="size-4 animate-spin" />
              <span className="font-mono text-xs">加载日志中…</span>
            </div>
          ) : error ? (
            <div className="flex h-full items-center justify-center font-mono text-xs text-danger">
              {message}
            </div>
          ) : log?.trim() ? (
            <pre className="font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-text-secondary">
              {log}
            </pre>
          ) : (
            <div className="flex h-full items-center justify-center font-mono text-xs text-text-muted">
              此运行没有可用日志
            </div>
          )}
        </div>

        <div className="flex justify-end">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
