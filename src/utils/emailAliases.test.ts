import { describe, it, expect } from 'vitest';
import { aliasesForHost, maskedEmailFields, type EmailAlias } from './emailAliases';

const alias = (domain: string, active = true): EmailAlias => ({ id: domain, alias_email: 'shop-123@mask.xorapass.com', domain_tag: domain, label: '', is_active: active });

describe('masked email privacy', () => {
  it('only returns active aliases for the current website', () => {
    const items = [alias('shop.example.com'), alias('unrelated.com'), alias('example.com', false)];
    expect(aliasesForHost(items, 'accounts.example.com')).toEqual([items[0]]);
    expect(aliasesForHost(items, 'example.com.evil.test')).toEqual([]);
  });
  it('keeps separate tenants on shared hosting separate', () => {
    expect(aliasesForHost([alias('alice.github.io')], 'bob.github.io')).toEqual([]);
  });
  it('retains existing custom fields when updating a saved credential', () => {
    expect(maskedEmailFields({ alias_id: 'existing', note: 'keep' })).toEqual({ alias_id: 'existing', note: 'keep' });
    expect(maskedEmailFields({ note: 'keep' }, {id:'new', email:'new@mask.xorapass.com'})).toEqual({note:'keep',is_masked_email:'true',alias_id:'new',alias_email:'new@mask.xorapass.com'});
  });
});
