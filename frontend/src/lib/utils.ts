import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Copy text to the clipboard, falling back to the legacy execCommand path
 * when the async Clipboard API is unavailable (e.g. plain-HTTP origins, where
 * `navigator.clipboard` is undefined outside secure contexts).
 */
export async function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch {
      // Fall through to the legacy path below.
    }
  }

  const textarea = document.createElement("textarea")
  textarea.value = text
  textarea.setAttribute("readonly", "")
  textarea.style.position = "fixed"
  textarea.style.top = "-9999px"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)
  textarea.select()
  try {
    const ok = document.execCommand("copy")
    if (!ok) throw new Error("execCommand copy failed")
  } finally {
    document.body.removeChild(textarea)
  }
}
