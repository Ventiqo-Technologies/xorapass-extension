// The navigation guard and content script are separate bundles in the same
// isolated world. Module-local flags cannot coordinate their overlay layers.
const stateKey = Symbol.for('xorapass.autofillSurface');
interface SurfaceState { blocks: Set<symbol>; listeners: Set<() => void> }
type SurfaceWindow = Window & { [stateKey]?: SurfaceState };

function stateFor(target: Window): SurfaceState {
  const owner = target as SurfaceWindow;
  return owner[stateKey] ||= { blocks: new Set(), listeners: new Set() };
}

function visibleStates(): SurfaceState[] {
  const own = stateFor(window);
  try {
    return window.top && window.top !== window ? [own, stateFor(window.top)] : [own];
  } catch { return [own]; }
}

export function isAutofillSuppressed(): boolean {
  return visibleStates().some(state => state.blocks.size > 0);
}

/** Registers an overlay's teardown, including late-loading same-origin frames. */
export function onAutofillSuppressed(listener: () => void): () => void {
  const states = visibleStates();
  for (const state of states) state.listeners.add(listener);
  if (isAutofillSuppressed()) listener();
  return () => { for (const state of states) state.listeners.delete(listener); };
}

/** The matching block owns its release; closing another overlay cannot unlock it. */
export function suppressAutofill(): () => void {
  const state = stateFor(window);
  const owner = Symbol('block');
  state.blocks.add(owner);
  for (const listener of state.listeners) listener();
  return () => { state.blocks.delete(owner); };
}

/** Never treat extension controls as website fields, including across shadows. */
export function isExtensionUiElement(element: Element): boolean {
  let node: Element | null = element;
  const seen = new Set<Element>();
  while (node && !seen.has(node)) {
    seen.add(node);
    if (node.id === 'xorapass-overlay-host' || node.hasAttribute?.('data-xorapass-ui')) return true;
    const root = node.getRootNode?.() as ShadowRoot | undefined;
    node = node.parentElement || root?.host || null;
  }
  return false;
}
