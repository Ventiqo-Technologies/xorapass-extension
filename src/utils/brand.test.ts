import { describe, it, expect } from 'vitest';
import { getBrandMetadata, getFaviconUrl } from './brand';

describe('Brand Icon & Portal Resolver', () => {
  it('resolves AWS SSO portal URLs correctly to bundled AWS icon', () => {
    const meta = getBrandMetadata('AWS Access Portal', 'login', 'https://d-90663f857a.awsapps.com/start/');
    expect(meta.logoUrl).toBe('/icons/aws.png');
  });

  it('resolves AWS console URLs correctly', () => {
    const meta = getBrandMetadata('AWS Production', 'login', 'https://signin.aws.amazon.com/console');
    expect(meta.logoUrl).toBe('/icons/aws.png');
  });

  it('resolves Okta tenant subdomains to okta favicon', () => {
    const meta = getBrandMetadata('Company Okta', 'login', 'https://mycompany.okta.com');
    expect(meta.faviconUrl).toBe(getFaviconUrl('okta.com'));
  });

  it('resolves GitHub to bundled GitHub icon', () => {
    const meta = getBrandMetadata('GitHub Account', 'login', 'https://github.com/login');
    expect(meta.logoUrl).toBe('/icons/github.png');
  });

  it('resolves Google / Gmail URLs to bundled Gmail icon', () => {
    const meta = getBrandMetadata('Work Mail', 'login', 'https://mail.google.com');
    expect(meta.logoUrl).toBe('/icons/gmail.png');
  });

  it('resolves Microsoft / Azure / Office URLs to bundled Microsoft icon', () => {
    const meta = getBrandMetadata('Azure Portal', 'login', 'https://portal.azure.com');
    expect(meta.logoUrl).toBe('/icons/microsoft.png');
  });

  it('resolves Atlassian cloud domains to atlassian favicon', () => {
    const meta = getBrandMetadata('Jira Board', 'login', 'https://company.atlassian.net');
    expect(meta.faviconUrl).toBe(getFaviconUrl('atlassian.com'));
  });

  it('falls back to Google favicon for generic websites', () => {
    const meta = getBrandMetadata('Some Random Blog', 'login', 'https://blog.example.com/login');
    expect(meta.faviconUrl).toBe(getFaviconUrl('blog.example.com'));
  });
});
