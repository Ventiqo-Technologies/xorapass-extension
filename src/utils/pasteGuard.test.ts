import { describe, it, expect } from 'vitest';
import { isAiSite, shouldGuard, coercePolicy, DEFAULT_POLICY } from './pasteGuard';

describe('isAiSite', () => {
  it('matches known AI registrable domains and their subdomains', () => {
    expect(isAiSite('chatgpt.com')).toBe(true);
    expect(isAiSite('chat.openai.com')).toBe(true);
    expect(isAiSite('claude.ai')).toBe(true);
    expect(isAiSite('www.perplexity.ai')).toBe(true);
    expect(isAiSite('v0.dev')).toBe(true);
    expect(isAiSite('cursor.com')).toBe(true);
    expect(isAiSite('bolt.new')).toBe(true);
    expect(isAiSite('chat.lmsys.org')).toBe(true);
    expect(isAiSite('kimi.ai')).toBe(true);
    expect(isAiSite('doubao.com')).toBe(true);
    expect(isAiSite('chat.qwen.ai')).toBe(true);
  });

  it('matches specific AI hosts on shared providers', () => {
    expect(isAiSite('gemini.google.com')).toBe(true);
    expect(isAiSite('copilot.microsoft.com')).toBe(true);
    expect(isAiSite('yiyan.baidu.com')).toBe(true);
    expect(isAiSite('tongyi.aliyun.com')).toBe(true);
    expect(isAiSite('xinghuo.xfyun.cn')).toBe(true);
  });

  it('does not match non-AI hosts on those shared providers', () => {
    expect(isAiSite('mail.google.com')).toBe(false);
    expect(isAiSite('www.microsoft.com')).toBe(false);
  });

  it('does not match ordinary sites', () => {
    expect(isAiSite('github.com')).toBe(false);
    expect(isAiSite('example.com')).toBe(false);
    expect(isAiSite('')).toBe(false);
  });
});

describe('shouldGuard', () => {
  it('never guards when mode is off', () => {
    expect(shouldGuard({ ...DEFAULT_POLICY, mode: 'off' }, 'chatgpt.com')).toBe(false);
  });

  it('guards AI sites only by default', () => {
    expect(shouldGuard(DEFAULT_POLICY, 'chatgpt.com')).toBe(true);
    expect(shouldGuard(DEFAULT_POLICY, 'example.com')).toBe(false);
  });

  it('guards everywhere when scope is all_sites', () => {
    const p = { ...DEFAULT_POLICY, scope: 'all_sites' as const };
    expect(shouldGuard(p, 'example.com')).toBe(true);
  });
});

describe('coercePolicy', () => {
  it('falls back to safe defaults for garbage input', () => {
    expect(coercePolicy(null)).toEqual(DEFAULT_POLICY);
    expect(coercePolicy({ mode: 'nonsense' })).toEqual(DEFAULT_POLICY);
  });

  it('forces allowDismiss=false in block mode', () => {
    const p = coercePolicy({ mode: 'block', allowDismiss: true });
    expect(p.mode).toBe('block');
    expect(p.allowDismiss).toBe(false);
  });

  it('preserves a valid admin warn policy', () => {
    const p = coercePolicy({ mode: 'warn', allowDismiss: false, scope: 'all_sites', source: 'admin' });
    expect(p).toEqual({ mode: 'warn', allowDismiss: false, scope: 'all_sites', source: 'admin' });
  });
});
