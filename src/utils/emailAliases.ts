import { isDomainMatch } from './siteTrust';

export interface EmailAlias {
  id: string;
  alias_email: string;
  domain_tag: string;
  label: string;
  is_active: boolean;
  admin_disabled?: boolean;
}

export function isMaskedEmail(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized.endsWith('@mask.xorapass.com') || normalized.endsWith('@dev.mask.xorapass.com');
}

/** Do not expose aliases belonging to unrelated sites to a content script. */
export function aliasesForHost(aliases: EmailAlias[], hostname: string): EmailAlias[] {
  return aliases.filter((a) => a.is_active && !a.admin_disabled && typeof a.id === 'string' &&
    typeof a.alias_email === 'string' && typeof a.domain_tag === 'string' &&
    isDomainMatch(hostname, a.domain_tag));
}

export function maskedEmailFields(existing: Record<string, string> | undefined, alias?: {id: string; email: string}): Record<string, string> {
  if (!alias) return { ...existing };
  return { ...existing, is_masked_email: 'true', alias_id: alias.id, alias_email: alias.email };
}
