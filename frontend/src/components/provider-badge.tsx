import { cn } from "@/lib/utils"

/**
 * Per-provider brand colours. Each provider gets a signature hue drawn from the
 * AI company's own palette (e.g. Anthropic's clay-orange, OpenAI's teal). The
 * badge renders a tinted chip whose text/dot use the brand colour and whose
 * background is a low-opacity wash of the same hue, so it reads on both the
 * light and dark themes without needing per-mode overrides.
 *
 * Keep this vocabulary in sync with the Rust provider registry
 * (`crates/aipocket-prober/src/provider.rs`).
 */
export type ProviderName =
  | "openai"
  | "anthropic"
  | "deepseek"
  | "kimi"
  | "glm"
  | "qwen"
  | "siliconflow"
  | "google"
  | "groq"
  | "openrouter"
  | "azure_openai"
  | "vertex"
  | "gemini"
  | "cohere"
  | "replicate"
  | "together"
  | "fireworks"
  | "minimax"
  | "nvidia"
  | "ksyun"
  | "longcat"
  | "xai"
  | "qoder"
  | "kiro"
  | "aws_bedrock"
  | "cursor"
  | "windsurf"
  | "newapi"
  | "oneapi"
  | "litellm"
  | "gateway"
  | "ambiguous"
  | "unknown"

const PROVIDER_BRAND: Record<ProviderName, { label: string; color: string }> = {
  openai: { label: "OpenAI", color: "#10a37f" },
  anthropic: { label: "Anthropic", color: "#d97757" },
  deepseek: { label: "DeepSeek", color: "#4d6bfe" },
  kimi: { label: "Kimi", color: "#7c5cff" },
  glm: { label: "GLM", color: "#3859ff" },
  qwen: { label: "Qwen", color: "#a855f7" },
  siliconflow: { label: "SiliconFlow", color: "#00b3c4" },
  google: { label: "Google", color: "#4285f4" },
  groq: { label: "Groq", color: "#f55036" },
  openrouter: { label: "OpenRouter", color: "#6b5cff" },
  azure_openai: { label: "Azure OpenAI", color: "#0078d4" },
  vertex: { label: "Vertex AI", color: "#1a73e8" },
  gemini: { label: "Gemini", color: "#8e75b2" },
  cohere: { label: "Cohere", color: "#39594d" },
  replicate: { label: "Replicate", color: "#6f7b91" },
  together: { label: "Together", color: "#ff6b35" },
  fireworks: { label: "Fireworks", color: "#ed3d7d" },
  minimax: { label: "MiniMax", color: "#f59e0b" },
  nvidia: { label: "NVIDIA NIM", color: "#76b900" },
  ksyun: { label: "KSYUN MaaS", color: "#ff6a00" },
  longcat: { label: "LongCat", color: "#8b5cf6" },
  xai: { label: "xAI", color: "#111827" },
  qoder: { label: "Qoder", color: "#6750a4" },
  kiro: { label: "Kiro", color: "#938f9b" },
  aws_bedrock: { label: "AWS Bedrock", color: "#ff9900" },
  cursor: { label: "Cursor", color: "#0f172a" },
  windsurf: { label: "Windsurf", color: "#00bfa5" },
  newapi: { label: "NewAPI", color: "#0ea5e9" },
  oneapi: { label: "OneAPI", color: "#06b6d4" },
  litellm: { label: "LiteLLM", color: "#6366f1" },
  gateway: { label: "Gateway", color: "#64748b" },
  ambiguous: { label: "Ambiguous", color: "#d97706" },
  unknown: { label: "Unknown", color: "#7d8db0" },
}

// Prominent steel-blue-gray for providers not in the brand map — clearly visible
// in both themes and distinct from gateway (#64748b) and every brand hue.
const FALLBACK = { label: "", color: "#7d8db0" }

/** Look up a provider's brand descriptor (label + hex colour), case-insensitively. */
export function providerBrand(provider: string): { label: string; color: string } {
  const brand = (PROVIDER_BRAND as Partial<Record<string, { label: string; color: string }>>)[
    provider.toLowerCase()
  ]
  if (brand) return brand
  return { ...FALLBACK, label: provider }
}

/** The brand hex colour for a provider — for text/number accents (e.g. stats). */
export function providerBrandColor(provider: string): string {
  return providerBrand(provider).color
}

export interface ProviderBadgeProps {
  provider: string
  className?: string
}

/** A tinted chip showing the provider name in its AI company's brand colour. */
export function ProviderBadge({ provider, className }: Readonly<ProviderBadgeProps>) {
  const { label, color } = providerBrand(provider)
  return (
    <span
      className={cn(
        "inline-flex w-fit max-w-full shrink-0 items-center gap-1.5 rounded-sm px-2 py-0.5 font-mono text-[11px] font-medium",
        className,
      )}
      style={{
        color,
        // 14% wash of the brand colour for the chip background, brand-tinted border.
        backgroundColor: `${color}24`,
        boxShadow: `inset 0 0 0 1px ${color}40`,
      }}
    >
      <span className="size-1.5 shrink-0 rounded-full" style={{ backgroundColor: color }} />
      {label || provider}
    </span>
  )
}
