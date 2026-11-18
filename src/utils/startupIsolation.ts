/**
 * Startup Isolation: domains that must be exempted from document_start hooks
 * and navigation guards.
 *
 * These are first-party trusted web applications with highly timing-sensitive
 * boot sequences, canvas rendering engines, or complex WASM/SPA lifecycles
 * (e.g. AWS CloudScape, WhatsApp Web QR renderer, Microsoft SharePoint / Office
 * Online document viewers and editors, Atlassian Jira/Confluence, Google Docs, Figma).
 *
 * They are already verified first-party platforms in the domain-risk engine.
 * Installing document_start navigation/input guards (shieldNav) or monkey-patching
 * prototypes in the MAIN world (pageHooks) can interfere with their canvas font
 * measurement, synthetic event detection, or initialization, breaking file
 * viewers and SPAs.
 */

const ISOLATED_EXACT_OR_SUFFIX_DOMAINS: readonly string[] = [
  // WhatsApp Web
  'web.whatsapp.com',
  'whatsapp.com',

  // AWS Console & Management
  'aws.amazon.com',
  'signin.aws',
  'awsapps.com',

  // Microsoft SharePoint, OneDrive, and Office 365
  'sharepoint.com',
  'sharepoint-df.com',
  'office.com',
  'office365.com',
  'office.net',
  'officeapps.live.com',
  'onedrive.live.com',
  'onedrive.com',
  'microsoft.com',
  'microsoftonline.com',
  'microsoft365.com',
  'cloud.microsoft',
  'live.com',

  // Atlassian Cloud (Jira & Confluence rich-text editors, boards)
  'atlassian.net',
  'atlassian.com',
  'jira.com',
  'trello.com',
  'bitbucket.org',

  // Google Workspace Editors (Docs, Sheets, Slides, Drive canvas renderers)
  'docs.google.com',
  'drive.google.com',

  // Heavy Canvas/WebGL Design & Creative Tools
  'figma.com',
  'canva.com',
];

export function isStartupIsolatedHost(hostname: string): boolean {
  if (!hostname) return false;
  const host = hostname.toLowerCase();

  for (const domain of ISOLATED_EXACT_OR_SUFFIX_DOMAINS) {
    if (host === domain || host.endsWith('.' + domain)) {
      return true;
    }
  }

  return false;
}
