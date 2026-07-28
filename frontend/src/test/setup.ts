import "@testing-library/jest-dom/vitest"
import { cleanup } from "@testing-library/react"
import { afterEach } from "vitest"

// jsdom 30 can throw while resolving Tailwind's CSS variables in role queries.
// Accessibility checks only need a stable declaration object in unit tests.
const nativeGetComputedStyle = window.getComputedStyle.bind(window)
window.getComputedStyle = (element, pseudoElement) => {
  try {
    return nativeGetComputedStyle(element, pseudoElement)
  } catch {
    return element instanceof HTMLElement ? element.style : nativeGetComputedStyle(element, pseudoElement)
  }
}

afterEach(cleanup)
