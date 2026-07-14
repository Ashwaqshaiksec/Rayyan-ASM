// Split out from OnboardingTutorial.tsx: react-refresh/only-export-components
// flags any non-component export sitting in the same file as a component's
// default export, since it breaks Vite's fast-refresh boundary. This event
// name + dispatcher is the only such export, so it lives here instead.
export const OPEN_TUTORIAL_EVENT = 'rayyan:open-tutorial'

/** Called by the header help button to relaunch the walkthrough on demand. */
export function reopenTutorial() {
  window.dispatchEvent(new Event(OPEN_TUTORIAL_EVENT))
}
