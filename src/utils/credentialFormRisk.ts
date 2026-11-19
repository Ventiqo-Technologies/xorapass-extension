import type { DomainRiskAssessment } from './domainRisk';
import type { FormThreatContext } from './domainRiskService';
import type { PageSignals } from './pageSignals';
import { registrableDomain, isFreeHostingHost, isUserContentHost, normalizeHostname } from './siteTrust';
import { BRAND_CATALOG, brandOwnsHost, type CatalogBrand } from './brandCatalog';

/**
 * Checks whether pageHost and actionHost belong to the same authentic corporate entity:
 * 1. Exact host match (e.g. www.zoho.com -> www.zoho.com)
 * 2. Same registrable domain (e.g. www.zoho.com -> accounts.zoho.com), provided neither
 *    is on a multi-tenant user content or free hosting platform.
 * 3. Verified brand sibling domains in the brand catalog (e.g. office.com -> login.microsoftonline.com)
 */
export function isSameBrandOrSite(
  pageHost: string,
  actionHost: string,
  brands: readonly CatalogBrand[] = BRAND_CATALOG
): boolean {
  const normPage = normalizeHostname(pageHost);
  const normAction = normalizeHostname(actionHost);
  if (!normPage || !normAction) return false;

  // 1. Exact hostname match
  if (normPage === normAction) return true;

  // 2. Same registrable domain (e.g. www.zoho.com and accounts.zoho.com)
  const pageDomain = registrableDomain(normPage);
  const actionDomain = registrableDomain(normAction);
  if (
    pageDomain &&
    actionDomain &&
    pageDomain === actionDomain &&
    !isUserContentHost(normPage) &&
    !isFreeHostingHost(normPage) &&
    !isUserContentHost(normAction) &&
    !isFreeHostingHost(normAction)
  ) {
    return true;
  }

  // 3. Known authentic enterprise SSO / brand sibling domains (e.g. office.com -> login.microsoftonline.com)
  for (const brand of brands) {
    if (brandOwnsHost(brand, normPage) && brandOwnsHost(brand, normAction)) {
      return true;
    }
  }

  return false;
}

/** A saved/trusted page does not authorize sending a password elsewhere. */
export function credentialFormReason(
  currentUrl: string,
  form?: FormThreatContext,
  signals?: PageSignals,
  brands: readonly CatalogBrand[] = BRAND_CATALOG
): string | null {
  if (!(form?.hasPasswordField || form?.isLoginForm || (signals?.password_field_count ?? 0) > 0)) return null;
  try {
    const page = new URL(currentUrl);
    const action = new URL(form?.actionUrl || currentUrl, page);
    if (!/^https?:$/.test(action.protocol)) return 'This login form has an unsupported credential destination.';
    if (action.protocol === 'http:' || signals?.form_action_insecure) return 'This login form sends your password over an unencrypted connection.';

    // Check if the destination matches the page origin, same registrable domain, or authentic brand sibling
    const isSameDestination =
      action.protocol === page.protocol &&
      action.port === page.port &&
      isSameBrandOrSite(page.hostname, action.hostname, brands);

    if (!isSameDestination || signals?.form_action_cross_origin) {
      return 'This login form sends your password to a different origin.';
    }
  } catch {
    return 'The destination of this login form could not be verified.';
  }
  return null;
}

export function applyCredentialFormRisk(
  risk: DomainRiskAssessment,
  currentUrl: string,
  form?: FormThreatContext,
  signals?: PageSignals,
  brands: readonly CatalogBrand[] = BRAND_CATALOG
): DomainRiskAssessment {
  const reason = credentialFormReason(currentUrl, form, signals, brands);
  if (!reason || risk.decision === 'block') return risk;
  return {
    ...risk,
    riskScore: Math.max(risk.riskScore, 70),
    riskLevel: 'high',
    decision: 'require_approval',
    reasons: Array.from(new Set([reason, ...risk.reasons])),
    safeWarningMessage: reason,
  };
}

