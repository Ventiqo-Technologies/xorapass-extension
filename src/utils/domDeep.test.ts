import { describe, it, expect } from 'vitest';
import { querySelectorAllDeep } from './domDeep';

// Lightweight mock element structure for testing shadow traversal in Node/Vitest
interface MockElement {
  id?: string;
  tagName: string;
  shadowRoot?: MockParentNode | null;
  attributes: Record<string, string>;
  querySelectorAll: (selector: string) => MockElement[];
}

interface MockParentNode {
  querySelectorAll: (selector: string) => MockElement[];
}

function createMockRoot(
  elements: MockElement[],
  shadowRoots: { host: MockElement; root: MockParentNode }[] = []
): MockParentNode {
  for (const { host, root } of shadowRoots) {
    host.shadowRoot = root;
  }

  return {
    querySelectorAll: (selector: string): MockElement[] => {
      if (selector === '*') {
        return [...elements];
      }
      if (selector === 'input[type="password"]') {
        return elements.filter(
          (el) => el.tagName === 'INPUT' && el.attributes['type'] === 'password'
        );
      }
      if (selector === 'input') {
        return elements.filter((el) => el.tagName === 'INPUT');
      }
      return [];
    },
  };
}

describe('querySelectorAllDeep', () => {
  it('finds elements in standard light DOM', () => {
    const userInput: MockElement = {
      id: 'username',
      tagName: 'INPUT',
      attributes: { type: 'text' },
      querySelectorAll: () => [],
    };
    const passInput: MockElement = {
      id: 'password',
      tagName: 'INPUT',
      attributes: { type: 'password' },
      querySelectorAll: () => [],
    };

    const root = createMockRoot([userInput, passInput]);
    const found = querySelectorAllDeep<any>(root as any, 'input');
    expect(found.length).toBe(2);
    expect(found[0].id).toBe('username');
    expect(found[1].id).toBe('password');
  });

  it('pierces open Shadow DOM to find inputs inside Web Components', () => {
    const shadowPass: MockElement = {
      id: 'shadow-pass',
      tagName: 'INPUT',
      attributes: { type: 'password' },
      querySelectorAll: () => [],
    };

    const shadowRoot = createMockRoot([shadowPass]);

    const customHost: MockElement = {
      tagName: 'CUSTOM-LOGIN',
      attributes: {},
      querySelectorAll: () => [],
    };

    const root = createMockRoot([customHost], [{ host: customHost, root: shadowRoot }]);

    const found = querySelectorAllDeep<any>(root as any, 'input[type="password"]');
    expect(found.length).toBe(1);
    expect(found[0].id).toBe('shadow-pass');
  });

  it('handles nested shadow roots safely', () => {
    const deepPass: MockElement = {
      id: 'deep-pass',
      tagName: 'INPUT',
      attributes: { type: 'password' },
      querySelectorAll: () => [],
    };

    const childShadow = createMockRoot([deepPass]);

    const childHost: MockElement = {
      tagName: 'CHILD-EL',
      attributes: {},
      querySelectorAll: () => [],
    };

    const parentShadow = createMockRoot([childHost], [{ host: childHost, root: childShadow }]);

    const parentHost: MockElement = {
      tagName: 'PARENT-EL',
      attributes: {},
      querySelectorAll: () => [],
    };

    const root = createMockRoot([parentHost], [{ host: parentHost, root: parentShadow }]);

    const found = querySelectorAllDeep<any>(root as any, 'input[type="password"]');
    expect(found.length).toBe(1);
    expect(found[0].id).toBe('deep-pass');
  });

  it('gracefully handles empty or null root', () => {
    expect(querySelectorAllDeep(null as any, 'input')).toEqual([]);
  });
});
