import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { isAutofillSuppressed, isExtensionUiElement, onAutofillSuppressed, suppressAutofill } from './autofillSurface';

function world(top?: object) {
  const owner: {top?:object} = {};
  owner.top = top || owner;
  return owner;
}
beforeEach(() => vi.stubGlobal('window',world()));
afterEach(() => vi.unstubAllGlobals());

describe('full-page block autofill isolation',()=>{
  it('clears overlays as soon as a block starts',()=>{
    const clear=vi.fn();onAutofillSuppressed(clear);
    const release=suppressAutofill();
    expect(isAutofillSuppressed()).toBe(true);expect(clear).toHaveBeenCalledOnce();
    release();expect(isAutofillSuppressed()).toBe(false);
  });
  it('late-loading overlays see the navigation guard block immediately',()=>{
    suppressAutofill();const clear=vi.fn();onAutofillSuppressed(clear);
    expect(clear).toHaveBeenCalledOnce();expect(isAutofillSuppressed()).toBe(true);
  });
  it('independently loaded bundle copies share the isolated-world state',async()=>{
    suppressAutofill();vi.resetModules();
    const later=await import('./autofillSurface');
    const clear=vi.fn();later.onAutofillSuppressed(clear);
    expect(later.isAutofillSuppressed()).toBe(true);expect(clear).toHaveBeenCalledOnce();
  });
  it('closing one block cannot release another overlay’s block',()=>{
    const first=suppressAutofill(),second=suppressAutofill();
    first();first();expect(isAutofillSuppressed()).toBe(true);
    second();expect(isAutofillSuppressed()).toBe(false);
  });
  it('same-origin child frames also suppress their overlays for a top-page block',()=>{
    const top=window;const child=world(top);vi.stubGlobal('window',child);
    const clear=vi.fn();onAutofillSuppressed(clear);
    vi.stubGlobal('window',top);const release=suppressAutofill();
    vi.stubGlobal('window',child);expect(isAutofillSuppressed()).toBe(true);expect(clear).toHaveBeenCalledOnce();
    release();expect(isAutofillSuppressed()).toBe(false);
  });
  it('does not access a cross-origin top frame',()=>{
    const top=new Proxy({}, {get(){throw new Error('SecurityError');},set(){throw new Error('SecurityError');}});
    vi.stubGlobal('window',world(top));expect(isAutofillSuppressed()).toBe(false);
    const release=suppressAutofill();expect(isAutofillSuppressed()).toBe(true);release();
  });
  it('unsubscribed overlays are not retained for later blocks',()=>{
    const clear=vi.fn();const unsubscribe=onAutofillSuppressed(clear);unsubscribe();
    suppressAutofill();expect(clear).not.toHaveBeenCalled();
  });
});

describe('Shield UI is never a website autofill target',()=>{
  const element=(props:object={})=>({parentElement:null,getRootNode:()=>null,...props}) as unknown as Element;
  it('excludes a field inside a Shield host in light DOM',()=>{
    const host=element({id:'xorapass-overlay-host'});
    expect(isExtensionUiElement(element({parentElement:host}))).toBe(true);
  });
  it('excludes a field inside the Shield shadow root',()=>{
    const host=element({id:'xorapass-overlay-host'});
    expect(isExtensionUiElement(element({getRootNode:()=>({host})}))).toBe(true);
  });
  it('recognizes explicitly marked extension controls',()=>{
    expect(isExtensionUiElement(element({hasAttribute:(name:string)=>name==='data-xorapass-ui'}))).toBe(true);
  });
  it('keeps ordinary website Web Components eligible',()=>{
    const host=element({id:'website-login'});
    expect(isExtensionUiElement(element({getRootNode:()=>({host})}))).toBe(false);
  });
});
