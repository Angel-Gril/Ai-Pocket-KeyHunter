import { useEffect, useState } from "react"
import { AlertTriangle, Loader2, MessageSquare } from "lucide-react"
import type { ChatResponse } from "@/lib/api"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { cn } from "@/lib/utils"

export interface ChatTestDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  maskedKey: string
  models: string[]
  modelsLoading?: boolean
  pending?: boolean
  result: ChatResponse | null
  onSend: (model: string) => void
}

export function ChatTestDialog({
  open,
  onOpenChange,
  maskedKey,
  models,
  modelsLoading,
  pending,
  result,
  onSend,
}: Readonly<ChatTestDialogProps>) {
  const [model, setModel] = useState<string>("")

  useEffect(() => {
    if (!open) {
      setModel("")
      return
    }
    setModel((current) => (current && models.includes(current) ? current : models[0] ?? ""))
  }, [open, models])

  const hasModels = models.length > 0

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="border-border-primary bg-surface-raised">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-text-primary">
            <MessageSquare className="size-4 text-accent" />
            测试对话
          </DialogTitle>
          <DialogDescription className="font-mono text-xs text-text-muted">
            {maskedKey}
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-start gap-2 rounded-sm border border-warning/40 bg-warning-dim px-3 py-2.5 text-xs text-warning">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>此操作会向该密钥发起一次真实的对话请求，可能消耗账户额度。请谨慎使用。</span>
        </div>

        <div className="flex flex-col gap-2">
          <span className="font-sans text-xs font-medium text-text-secondary">选择模型</span>
          {hasModels ? (
            <Select value={model} onValueChange={setModel}>
              <SelectTrigger className="w-full border-border-primary bg-surface-overlay font-mono text-xs text-text-primary">
                <SelectValue placeholder="选择一个模型" />
              </SelectTrigger>
              <SelectContent>
                {models.map((name) => (
                  <SelectItem key={name} value={name} className="font-mono text-xs">
                    {name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <span className="rounded-sm border border-border-subtle bg-surface-inset px-3 py-2 font-mono text-xs text-text-muted">
              {modelsLoading ? "加载模型中…" : "暂无可用模型，请先点击该行的 “模型列表” 加载。"}
            </span>
          )}
        </div>

        {result ? (
          <div
            className={cn(
              "flex flex-col gap-1.5 rounded-sm border px-3 py-2.5 text-xs",
              result.success
                ? "border-success/40 bg-success-dim text-success"
                : "border-danger/40 bg-danger-dim text-danger",
            )}
          >
            <span className="font-mono font-semibold">
              {result.success ? "对话成功" : "对话失败"}
              {result.status_code !== null ? ` · HTTP ${result.status_code}` : ""}
              {result.consumes_credit ? " · 已消耗额度" : ""}
            </span>
            <span className="font-mono break-words text-text-secondary">
              {result.success ? result.snippet || "(无内容)" : result.error || "(未知错误)"}
            </span>
          </div>
        ) : null}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            关闭
          </Button>
          <Button onClick={() => model && onSend(model)} disabled={!model || pending}>
            {pending ? <Loader2 className="size-4 animate-spin" /> : <MessageSquare className="size-4" />}
            发送测试
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
