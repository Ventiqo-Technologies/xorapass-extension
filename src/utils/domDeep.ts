/**
 * domDeep.ts
 *
 * Provides recursive DOM utilities to pierce open Shadow DOM boundaries
 * (Web Components, Lit, Salesforce Lightning, Ionic, custom elements)
 * without fixed CSS selectors or fragile DOM assumptions.
 */

/**
 * Recursively queries elements matching `selector` across the light DOM and any open shadow roots.
 * Safe against cycles, missing APIs, and limits traversal depth.
 *
 * @param root Root node to query from (document or specific element / shadow root)
 * @param selector Standard CSS selector (e.g. 'input[type="password"]', 'input')
 * @param maxDepth Maximum shadow nesting depth to prevent infinite loops (default: 8)
 */
export function querySelectorAllDeep<T extends Element = Element>(
  root: ParentNode = typeof document !== 'undefined' ? document : (null as any),
  selector: string,
  maxDepth = 8
): T[] {
  if (!root) return [];
  const results: T[] = [];
  const queue: { node: ParentNode; depth: number }[] = [{ node: root, depth: 0 }];
  const seenRoots = new Set<ParentNode>();

  while (queue.length > 0) {
    const item = queue.shift();
    if (!item) break;
    const { node, depth } = item;

    if (seenRoots.has(node)) continue;
    seenRoots.add(node);

    try {
      if (typeof node.querySelectorAll === 'function') {
        const matched = node.querySelectorAll<T>(selector);
        for (let i = 0; i < matched.length; i++) {
          results.push(matched[i]);
        }
      }
    } catch {
      // Ignore querySelectorAll syntax errors or detached node exceptions
    }

    if (depth >= maxDepth) continue;

    try {
      if (typeof node.querySelectorAll === 'function') {
        const allDescendants = node.querySelectorAll('*');
        for (let i = 0; i < allDescendants.length; i++) {
          const el = allDescendants[i];
          const sr = el.shadowRoot;
          if (sr && !seenRoots.has(sr)) {
            queue.push({ node: sr, depth: depth + 1 });
          }
        }
      }
    } catch {
      // Ignore errors traversing descendants
    }
  }

  return results;
}
