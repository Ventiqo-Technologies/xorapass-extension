// AI-site awareness and paste-guard policy. Pure and dependency-light so it can
// be bundled into the content script, the background worker, and tests.

import { normalizeHostname, registrableDomain } from './siteTrust';

// ── Known AI tools ───────────────────────────────────────────────────────────
// Registrable domains that ARE AI tools end-to-end. Any host on these (incl.
// subdomains) is treated as an AI site.
const AI_REGISTRABLE_DOMAINS = new Set<string>([
  'openai.com',
  'chatgpt.com',
  'claude.ai',
  'anthropic.com',
  'perplexity.ai',
  'poe.com',
  'character.ai',
  'you.com',
  'phind.com',
  'mistral.ai',
  'cohere.com',
  'deepseek.com',
  'x.ai',
  'groq.com',
  'huggingface.co',
  'replicate.com',
  'together.ai',
  'pi.ai',
]);

// Specific hosts on shared providers where only that subdomain is an AI tool
// (the rest of the registrable domain is not).
const AI_EXACT_HOSTS = new Set<string>([
  'gemini.google.com',
  'bard.google.com',
  'aistudio.google.com',
  'notebooklm.google.com',
  'copilot.microsoft.com',
  'copilot.cloud.microsoft',
  'm365.cloud.microsoft',
  'duckduckgo.com', // hosts duck.ai chat
]);

/** True when the hostname belongs to a known AI tool / chat site. */
export function isAiSite(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  if (!host) return false;
  if (AI_EXACT_HOSTS.has(host)) return true;
  return AI_REGISTRABLE_DOMAINS.has(registrableDomain(host));
}

// ── Policy ───────────────────────────────────────────────────────────────────

export type PasteGuardMode =
  | 'off' // never intervene
  | 'warn' // warn on detected secrets; user may proceed if allowDismiss
  | 'block'; // warn and refuse to paste the raw secret (no "paste anyway")

export type PasteGuardScope = 'ai_sites' | 'all_sites';

export interface PastePolicy {
  mode: PasteGuardMode;
  /** Whether "Paste anyway" is offered on a warn. Ignored when mode is block. */
  allowDismiss: boolean;
  /** Where the guard runs. Defaults to AI sites only. */
  scope: PasteGuardScope;
  /** Where this policy came from — for display and precedence. */
  source: 'default' | 'user' | 'admin';
}

// Safe default when no user/admin policy is known: warn on AI sites, let the
// user dismiss false positives. Never silently blocks, never runs everywhere.
export const DEFAULT_POLICY: PastePolicy = {
  mode: 'warn',
  allowDismiss: true,
  scope: 'ai_sites',
  source: 'default',
};

/** Normalizes an untrusted (e.g. backend-sourced) policy object to a valid one. */
export function coercePolicy(input: unknown): PastePolicy {
  const p = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  const mode: PasteGuardMode =
    p.mode === 'off' || p.mode === 'block' || p.mode === 'warn' ? p.mode : DEFAULT_POLICY.mode;
  const scope: PasteGuardScope = p.scope === 'all_sites' ? 'all_sites' : 'ai_sites';
  const source =
    p.source === 'admin' || p.source === 'user' ? (p.source as PastePolicy['source']) : DEFAULT_POLICY.source;
  // Block mode inherently disallows dismissing.
  const allowDismiss = mode === 'block' ? false : p.allowDismiss !== false;
  return { mode, allowDismiss, scope, source };
}

/** Should the paste guard run for this page under this policy? */
export function shouldGuard(policy: PastePolicy, hostname: string): boolean {
  if (policy.mode === 'off') return false;
  if (policy.scope === 'all_sites') return true;
  return isAiSite(hostname);
}
