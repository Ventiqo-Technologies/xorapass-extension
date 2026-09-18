import React from 'react';
import {
  Github,
  Chrome,
  Cloud,
  Facebook,
  Slack,
  Server,
  Key,
  FileText,
  CreditCard,
  Terminal,
  Lock,
  Shield,
  Search
} from 'lucide-react';
import { extractHostname, registrableDomain } from './siteTrust';

export interface BrandMetadata {
  icon: React.ComponentType<any>;
  colorClass: string;
  borderClass: string;
  bgClass: string;
  logoUrl?: string;      // Static bundled PNG (highest priority)
  faviconUrl?: string;   // Dynamic favicon fetched from Google (second priority)
}

/**
 * Returns Google Favicons API URL for a given domain/host.
 */
export function getFaviconUrl(domain: string): string {
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}

export const getBrandMetadata = (label: string, category: string, url?: string): BrandMetadata => {
  const cleanLabel = (label || '').toLowerCase().trim();
  const domain = url ? extractHostname(url) : '';
  const rootDomain = domain ? registrableDomain(domain) : '';
  const cleanUrl = (url || '').toLowerCase();

  const isMatch = (tokens: string[], domains: string[] = []): boolean => {
    const labelMatch = tokens.some((t) => cleanLabel.includes(t));
    const urlMatch = tokens.some((t) => cleanUrl.includes(t));
    const domainMatch = domains.some((d) => domain === d || domain.endsWith('.' + d) || rootDomain === d);
    return labelMatch || urlMatch || domainMatch;
  };

  // ── 1. Cloud Infrastructure & Developer Platforms ─────────────────────────
  if (isMatch(['xorapass'], ['xorapass.com'])) {
    return { icon: Lock, colorClass: 'text-cyan-500', borderClass: 'border-cyan-500/25', bgClass: 'bg-cyan-500/10', logoUrl: '/icons/icon48.png' };
  }
  if (isMatch(['aws', 'amazon web services'], ['awsapps.com', 'amazonaws.com', 'signin.aws', 'aws.amazon.com'])) {
    return { icon: Cloud, colorClass: 'text-amber-500', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', logoUrl: '/icons/aws.png' };
  }
  if (isMatch(['github'], ['github.com', 'github.io', 'github.dev'])) {
    return { icon: Github, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', logoUrl: '/icons/github.png' };
  }
  if (isMatch(['gitlab'], ['gitlab.com', 'gitlab.io'])) {
    return { icon: Server, colorClass: 'text-orange-500', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('gitlab.com') };
  }
  if (isMatch(['docker'], ['docker.com', 'docker.io', 'hub.docker.com'])) {
    return { icon: Server, colorClass: 'text-blue-500', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', logoUrl: '/icons/docker.png' };
  }
  if (isMatch(['cloudflare'], ['cloudflare.com', 'cloudflareaccess.com'])) {
    return { icon: Cloud, colorClass: 'text-orange-400', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('cloudflare.com') };
  }
  if (isMatch(['digitalocean'], ['digitalocean.com'])) {
    return { icon: Server, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('digitalocean.com') };
  }
  if (isMatch(['vercel'], ['vercel.com', 'vercel.app'])) {
    return { icon: Server, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('vercel.com') };
  }
  if (isMatch(['netlify'], ['netlify.com', 'netlify.app'])) {
    return { icon: Server, colorClass: 'text-teal-400', borderClass: 'border-teal-500/25', bgClass: 'bg-teal-500/10', faviconUrl: getFaviconUrl('netlify.com') };
  }
  if (isMatch(['supabase'], ['supabase.com', 'supabase.co'])) {
    return { icon: Server, colorClass: 'text-emerald-400', borderClass: 'border-emerald-500/25', bgClass: 'bg-emerald-500/10', faviconUrl: getFaviconUrl('supabase.com') };
  }
  if (isMatch(['postman'], ['postman.com', 'getpostman.com'])) {
    return { icon: Key, colorClass: 'text-orange-400', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('postman.com') };
  }
  if (isMatch(['nvidia'], ['nvidia.com'])) {
    return { icon: Server, colorClass: 'text-green-500', borderClass: 'border-green-500/25', bgClass: 'bg-green-500/10', logoUrl: '/icons/nvidia.png' };
  }
  if (isMatch(['google cloud', 'gcp'], ['cloud.google.com', 'console.cloud.google.com'])) {
    return { icon: Cloud, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('cloud.google.com') };
  }
  if (isMatch(['heroku'], ['heroku.com', 'herokuapp.com'])) {
    return { icon: Server, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('heroku.com') };
  }
  if (isMatch(['render'], ['render.com'])) {
    return { icon: Server, colorClass: 'text-indigo-400', borderClass: 'border-indigo-500/25', bgClass: 'bg-indigo-500/10', faviconUrl: getFaviconUrl('render.com') };
  }
  if (isMatch(['terraform', 'hashicorp', 'vault'], ['app.terraform.io', 'hashicorp.com'])) {
    return { icon: Server, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('hashicorp.com') };
  }
  if (isMatch(['datadog'], ['datadoghq.com'])) {
    return { icon: Shield, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('datadoghq.com') };
  }
  if (isMatch(['new relic', 'newrelic'], ['newrelic.com'])) {
    return { icon: Shield, colorClass: 'text-teal-400', borderClass: 'border-teal-500/25', bgClass: 'bg-teal-500/10', faviconUrl: getFaviconUrl('newrelic.com') };
  }
  if (isMatch(['pagerduty'], ['pagerduty.com'])) {
    return { icon: Shield, colorClass: 'text-green-400', borderClass: 'border-green-500/25', bgClass: 'bg-green-500/10', faviconUrl: getFaviconUrl('pagerduty.com') };
  }
  if (isMatch(['sentry'], ['sentry.io'])) {
    return { icon: Shield, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('sentry.io') };
  }

  // ── 2. Enterprise SSO & Identity Providers ────────────────────────────────
  if (isMatch(['okta'], ['okta.com', 'oktapreview.com', 'okta-emea.com'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('okta.com') };
  }
  if (isMatch(['onelogin'], ['onelogin.com'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('onelogin.com') };
  }
  if (isMatch(['auth0'], ['auth0.com'])) {
    return { icon: Shield, colorClass: 'text-orange-400', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('auth0.com') };
  }
  if (isMatch(['crowdstrike'], ['crowdstrike.com'])) {
    return { icon: Shield, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', faviconUrl: getFaviconUrl('crowdstrike.com') };
  }
  if (isMatch(['palo alto', 'paloalto', 'prisma'], ['paloaltonetworks.com'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('paloaltonetworks.com') };
  }
  if (isMatch(['sentinelone'], ['sentinelone.com'])) {
    return { icon: Shield, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('sentinelone.com') };
  }
  if (isMatch(['1password', 'onepassword'], ['1password.com'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('1password.com') };
  }
  if (isMatch(['bitwarden'], ['bitwarden.com'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('bitwarden.com') };
  }

  // ── 3. Google, Microsoft, Apple & Email Suites ────────────────────────────
  if (isMatch(['gmail'], ['mail.google.com'])) {
    return { icon: Chrome, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', logoUrl: '/icons/gmail.png' };
  }
  if (isMatch(['google', 'youtube', 'chrome'], ['google.com', 'youtube.com', 'googlemail.com'])) {
    return { icon: Chrome, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', logoUrl: '/icons/gmail.png' };
  }
  if (isMatch(['microsoft', 'azure', 'outlook', 'office', 'windows'], ['microsoft.com', 'microsoftonline.com', 'azure.com', 'office.com', 'outlook.com', 'live.com', 'sharepoint.com', 'windows.net'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', logoUrl: '/icons/microsoft.png' };
  }
  if (isMatch(['apple', 'icloud'], ['apple.com', 'icloud.com'])) {
    return { icon: Shield, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('apple.com') };
  }
  if (isMatch(['yahoo'], ['yahoo.com', 'mail.yahoo.com', 'ymail.com'])) {
    return { icon: Chrome, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', logoUrl: '/icons/yahoo.png' };
  }
  if (isMatch(['proton', 'protonmail'], ['proton.me', 'protonmail.com'])) {
    return { icon: Shield, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('proton.me') };
  }
  if (isMatch(['zoho'], ['zoho.com', 'zoho.eu', 'zoho.in'])) {
    return { icon: Shield, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', faviconUrl: getFaviconUrl('zoho.com') };
  }
  if (isMatch(['brevo'], ['brevo.com'])) {
    return { icon: Chrome, colorClass: 'text-green-400', borderClass: 'border-green-500/25', bgClass: 'bg-green-500/10', logoUrl: '/icons/brevo.png' };
  }
  if (isMatch(['sendgrid'], ['sendgrid.com'])) {
    return { icon: Chrome, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', logoUrl: '/icons/sendgrid.png' };
  }

  // ── 4. SaaS & Productivity Platforms ──────────────────────────────────────
  if (isMatch(['atlassian', 'jira', 'confluence', 'trello'], ['atlassian.com', 'atlassian.net', 'jira.com', 'confluence.cloud', 'trello.com'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('atlassian.com') };
  }
  if (isMatch(['slack'], ['slack.com'])) {
    return { icon: Slack, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('slack.com') };
  }
  if (isMatch(['notion'], ['notion.so', 'notion.site'])) {
    return { icon: FileText, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('notion.so') };
  }
  if (isMatch(['figma'], ['figma.com'])) {
    return { icon: Shield, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('figma.com') };
  }
  if (isMatch(['linear'], ['linear.app'])) {
    return { icon: Shield, colorClass: 'text-indigo-400', borderClass: 'border-indigo-500/25', bgClass: 'bg-indigo-500/10', faviconUrl: getFaviconUrl('linear.app') };
  }
  if (isMatch(['salesforce'], ['salesforce.com', 'force.com'])) {
    return { icon: Cloud, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('salesforce.com') };
  }
  if (isMatch(['hubspot'], ['hubspot.com'])) {
    return { icon: Shield, colorClass: 'text-orange-400', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('hubspot.com') };
  }
  if (isMatch(['zendesk'], ['zendesk.com'])) {
    return { icon: Shield, colorClass: 'text-teal-400', borderClass: 'border-teal-500/25', bgClass: 'bg-teal-500/10', faviconUrl: getFaviconUrl('zendesk.com') };
  }
  if (isMatch(['dropbox'], ['dropbox.com'])) {
    return { icon: Cloud, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('dropbox.com') };
  }
  if (isMatch(['docusign'], ['docusign.com', 'docusign.net'])) {
    return { icon: FileText, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('docusign.com') };
  }
  if (isMatch(['fortinet', 'fortigate'], ['fortinet.com'])) {
    return { icon: Shield, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', logoUrl: '/icons/fortinet.png' };
  }
  if (isMatch(['zoom'], ['zoom.us', 'zoom.com'])) {
    return { icon: Chrome, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('zoom.us') };
  }
  if (isMatch(['intercom'], ['intercom.com', 'intercom.io'])) {
    return { icon: Chrome, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('intercom.com') };
  }
  if (isMatch(['freshdesk', 'freshworks'], ['freshdesk.com', 'freshworks.com'])) {
    return { icon: Chrome, colorClass: 'text-teal-400', borderClass: 'border-teal-500/25', bgClass: 'bg-teal-500/10', faviconUrl: getFaviconUrl('freshworks.com') };
  }
  if (isMatch(['servicenow'], ['service-now.com', 'servicenow.com'])) {
    return { icon: Shield, colorClass: 'text-green-400', borderClass: 'border-green-500/25', bgClass: 'bg-green-500/10', faviconUrl: getFaviconUrl('servicenow.com') };
  }
  if (isMatch(['monday'], ['monday.com'])) {
    return { icon: Shield, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', faviconUrl: getFaviconUrl('monday.com') };
  }
  if (isMatch(['asana'], ['asana.com'])) {
    return { icon: Shield, colorClass: 'text-pink-400', borderClass: 'border-pink-500/25', bgClass: 'bg-pink-500/10', faviconUrl: getFaviconUrl('asana.com') };
  }
  if (isMatch(['clickup'], ['clickup.com'])) {
    return { icon: Shield, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('clickup.com') };
  }
  if (isMatch(['airtable'], ['airtable.com'])) {
    return { icon: FileText, colorClass: 'text-amber-400', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', faviconUrl: getFaviconUrl('airtable.com') };
  }
  if (isMatch(['miro'], ['miro.com'])) {
    return { icon: FileText, colorClass: 'text-amber-400', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', faviconUrl: getFaviconUrl('miro.com') };
  }

  // ── 5. AI & Machine Learning ──────────────────────────────────────────────
  if (isMatch(['openai', 'chatgpt'], ['openai.com', 'chatgpt.com'])) {
    return { icon: Shield, colorClass: 'text-emerald-400', borderClass: 'border-emerald-500/25', bgClass: 'bg-emerald-500/10', logoUrl: '/icons/openai.png' };
  }
  if (isMatch(['claude', 'anthropic'], ['anthropic.com', 'claude.ai'])) {
    return { icon: Shield, colorClass: 'text-amber-500', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', logoUrl: '/icons/claude-ai.png' };
  }
  if (isMatch(['perplexity'], ['perplexity.ai'])) {
    return { icon: Search, colorClass: 'text-teal-400', borderClass: 'border-teal-500/25', bgClass: 'bg-teal-500/10', faviconUrl: getFaviconUrl('perplexity.ai') };
  }
  if (isMatch(['huggingface', 'hugging face'], ['huggingface.co'])) {
    return { icon: Server, colorClass: 'text-amber-400', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', faviconUrl: getFaviconUrl('huggingface.co') };
  }
  if (isMatch(['gemini', 'google ai', 'google deepmind'], ['gemini.google.com', 'ai.google.dev', 'deepmind.google'])) {
    return { icon: Shield, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('gemini.google.com') };
  }
  if (isMatch(['mistral'], ['mistral.ai', 'console.mistral.ai'])) {
    return { icon: Shield, colorClass: 'text-orange-400', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('mistral.ai') };
  }
  if (isMatch(['grok', 'xai'], ['x.ai', 'grok.com'])) {
    return { icon: Shield, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('x.ai') };
  }
  if (isMatch(['midjourney'], ['midjourney.com'])) {
    return { icon: Shield, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('midjourney.com') };
  }

  // ── 6. Payments & E-Commerce ──────────────────────────────────────────────
  if (isMatch(['stripe'], ['stripe.com'])) {
    return { icon: CreditCard, colorClass: 'text-indigo-400', borderClass: 'border-indigo-500/25', bgClass: 'bg-indigo-500/10', faviconUrl: getFaviconUrl('stripe.com') };
  }
  if (isMatch(['paypal'], ['paypal.com', 'paypal.me'])) {
    return { icon: CreditCard, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('paypal.com') };
  }
  if (isMatch(['coinbase'], ['coinbase.com'])) {
    return { icon: CreditCard, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('coinbase.com') };
  }
  if (isMatch(['binance'], ['binance.com'])) {
    return { icon: CreditCard, colorClass: 'text-amber-400', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', faviconUrl: getFaviconUrl('binance.com') };
  }
  if (isMatch(['shopify'], ['shopify.com', 'myshopify.com'])) {
    return { icon: CreditCard, colorClass: 'text-emerald-400', borderClass: 'border-emerald-500/25', bgClass: 'bg-emerald-500/10', faviconUrl: getFaviconUrl('shopify.com') };
  }
  if (isMatch(['amazon'], ['amazon.com'])) {
    return { icon: Cloud, colorClass: 'text-amber-500', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', logoUrl: '/icons/aws.png' };
  }
  if (isMatch(['wise', 'transferwise'], ['wise.com'])) {
    return { icon: CreditCard, colorClass: 'text-emerald-400', borderClass: 'border-emerald-500/25', bgClass: 'bg-emerald-500/10', faviconUrl: getFaviconUrl('wise.com') };
  }
  if (isMatch(['revolut'], ['revolut.com'])) {
    return { icon: CreditCard, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('revolut.com') };
  }
  if (isMatch(['brex'], ['brex.com'])) {
    return { icon: CreditCard, colorClass: 'text-indigo-400', borderClass: 'border-indigo-500/25', bgClass: 'bg-indigo-500/10', faviconUrl: getFaviconUrl('brex.com') };
  }
  if (isMatch(['paddle'], ['paddle.com'])) {
    return { icon: CreditCard, colorClass: 'text-green-400', borderClass: 'border-green-500/25', bgClass: 'bg-green-500/10', faviconUrl: getFaviconUrl('paddle.com') };
  }

  // ── 7. Social, Media & Entertainment ──────────────────────────────────────
  if (isMatch(['facebook', 'meta'], ['facebook.com', 'meta.com', 'messenger.com'])) {
    return { icon: Facebook, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', logoUrl: '/icons/facebook.png' };
  }
  if (isMatch(['instagram'], ['instagram.com'])) {
    return { icon: Facebook, colorClass: 'text-pink-400', borderClass: 'border-pink-500/25', bgClass: 'bg-pink-500/10', logoUrl: '/icons/instagram.png' };
  }
  if (isMatch(['linkedin'], ['linkedin.com'])) {
    return { icon: Facebook, colorClass: 'text-blue-500', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', faviconUrl: getFaviconUrl('linkedin.com') };
  }
  if (isMatch(['twitter', ' x '], ['twitter.com', 'x.com'])) {
    return { icon: Shield, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('x.com') };
  }
  if (isMatch(['netflix'], ['netflix.com'])) {
    return { icon: Shield, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', faviconUrl: getFaviconUrl('netflix.com') };
  }
  if (isMatch(['spotify'], ['spotify.com'])) {
    return { icon: Shield, colorClass: 'text-emerald-400', borderClass: 'border-emerald-500/25', bgClass: 'bg-emerald-500/10', faviconUrl: getFaviconUrl('spotify.com') };
  }
  if (isMatch(['tiktok'], ['tiktok.com'])) {
    return { icon: Shield, colorClass: 'text-slate-200', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', faviconUrl: getFaviconUrl('tiktok.com') };
  }
  if (isMatch(['reddit'], ['reddit.com', 'redd.it'])) {
    return { icon: Chrome, colorClass: 'text-orange-400', borderClass: 'border-orange-500/25', bgClass: 'bg-orange-500/10', faviconUrl: getFaviconUrl('reddit.com') };
  }
  if (isMatch(['discord'], ['discord.com', 'discord.gg'])) {
    return { icon: Chrome, colorClass: 'text-indigo-400', borderClass: 'border-indigo-500/25', bgClass: 'bg-indigo-500/10', faviconUrl: getFaviconUrl('discord.com') };
  }
  if (isMatch(['twitch'], ['twitch.tv'])) {
    return { icon: Chrome, colorClass: 'text-purple-400', borderClass: 'border-purple-500/25', bgClass: 'bg-purple-500/10', faviconUrl: getFaviconUrl('twitch.tv') };
  }
  if (isMatch(['pinterest'], ['pinterest.com', 'pin.it'])) {
    return { icon: Chrome, colorClass: 'text-red-400', borderClass: 'border-red-500/25', bgClass: 'bg-red-500/10', faviconUrl: getFaviconUrl('pinterest.com') };
  }
  if (isMatch(['whatsapp'], ['whatsapp.com', 'wa.me'])) {
    return { icon: Chrome, colorClass: 'text-emerald-400', borderClass: 'border-emerald-500/25', bgClass: 'bg-emerald-500/10', faviconUrl: getFaviconUrl('whatsapp.com') };
  }

  // ── 8. Generic keyword categories ─────────────────────────────────────────
  if (cleanLabel.includes('ssh')) {
    return { icon: Terminal, colorClass: 'text-yellow-400', borderClass: 'border-yellow-500/25', bgClass: 'bg-yellow-500/10', logoUrl: '/icons/ssh.png' };
  }
  if (cleanLabel.includes('api')) {
    return { icon: Key, colorClass: 'text-yellow-400', borderClass: 'border-yellow-500/25', bgClass: 'bg-yellow-500/10', logoUrl: '/icons/api.png' };
  }
  if (cleanLabel.includes('business') || cleanLabel.includes('work') || cleanLabel.includes('office')) {
    return { icon: Shield, colorClass: 'text-slate-300', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', logoUrl: '/icons/business.png' };
  }
  if (cleanLabel.includes('email') || cleanLabel.includes('mail')) {
    return { icon: Chrome, colorClass: 'text-slate-300', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', logoUrl: '/icons/email.png' };
  }
  if (cleanLabel.includes('social') || cleanLabel.includes('network') || cleanLabel.includes('chat')) {
    return { icon: Facebook, colorClass: 'text-blue-400', borderClass: 'border-blue-500/25', bgClass: 'bg-blue-500/10', logoUrl: '/icons/social.png' };
  }
  if (cleanLabel.includes('search')) {
    return { icon: Search, colorClass: 'text-slate-300', borderClass: 'border-slate-700', bgClass: 'bg-slate-800', logoUrl: '/icons/search.png' };
  }

  // ── 9. Dynamic Favicon from URL domain ────────────────────────────────────
  if (domain) {
    return {
      icon: Lock,
      colorClass: 'text-cyan-400',
      borderClass: 'border-cyan-500/25',
      bgClass: 'bg-cyan-500/10',
      faviconUrl: getFaviconUrl(domain)
    };
  }

  // ── 10. Category-specific fallbacks ───────────────────────────────────────
  switch (category) {
    case 'note':
      return { icon: FileText, colorClass: 'text-cyan-400', borderClass: 'border-cyan-500/25', bgClass: 'bg-cyan-500/10' };
    case 'card':
      return { icon: CreditCard, colorClass: 'text-teal-400', borderClass: 'border-teal-500/25', bgClass: 'bg-teal-500/10' };
    case 'sshkey':
      return { icon: Terminal, colorClass: 'text-yellow-400', borderClass: 'border-yellow-500/25', bgClass: 'bg-yellow-500/10' };
    case 'aws':
      return { icon: Cloud, colorClass: 'text-amber-500', borderClass: 'border-amber-500/25', bgClass: 'bg-amber-500/10', logoUrl: '/icons/aws.png' };
    default:
      return { icon: Lock, colorClass: 'text-cyan-400', borderClass: 'border-cyan-500/25', bgClass: 'bg-cyan-500/10' };
  }
};
