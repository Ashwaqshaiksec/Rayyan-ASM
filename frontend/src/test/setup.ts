import '@testing-library/jest-dom'
import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => {
  cleanup()
})

// jsdom doesn't implement ResizeObserver, but Recharts' ResponsiveContainer
// requires it. Without this stub, any page rendering a chart throws in
// effects and every test in that file fails with "ResizeObserver is not
// defined" regardless of what the test actually asserts.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// @ts-expect-error -- not in the jsdom lib typings
global.ResizeObserver = ResizeObserverStub

// Silence react-hot-toast in tests
vi.mock('react-hot-toast', () => ({
  default: { error: vi.fn(), success: vi.fn() },
  toast: { error: vi.fn(), success: vi.fn() },
}))
