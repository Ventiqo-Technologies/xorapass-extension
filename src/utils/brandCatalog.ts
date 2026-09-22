// Built-in catalog of commonly phished brands.
//
// Used by the LOCAL checks so lookalike detection works even when the vault
// is locked or the user has saved few sites (the saved-site comparison alone
// compares against nothing then). `token` is the BRAND_LEXICON token that
// page signals report (utils/pageSignals.ts); `domains` are the registrable
// domains the brand legitimately owns. The backend can add brands without an
// extension release (Shield config "extra_brands", see mergeExtraBrands).

export interface CatalogBrand {
  token: string;
  name: string;
  domains: string[];
}

export const BRAND_CATALOG: readonly CatalogBrand[] = [
  { token: 'paypal', name: 'PayPal', domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  { token: 'microsoft', name: 'Microsoft', domains: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com', 'bing.com', 'azure.com', 'microsoft365.com', 'msauth.net', 'msftauth.net', 'skype.com', 'xbox.com', 'sharepoint.com', 'onedrive.com', 'windows.com'] },
  { token: 'office365', name: 'Microsoft 365', domains: ['office.com', 'microsoft.com', 'microsoftonline.com', 'microsoft365.com', 'live.com', 'sharepoint.com'] },
  { token: 'outlook', name: 'Outlook', domains: ['outlook.com', 'live.com', 'office.com', 'microsoft.com', 'microsoftonline.com'] },
  { token: 'google', name: 'Google', domains: ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com', 'google.co.uk', 'google.de', 'google.fr', 'google.co.in', 'google.ca', 'google.com.au'] },
  { token: 'gmail', name: 'Gmail', domains: ['gmail.com', 'google.com'] },
  { token: 'apple', name: 'Apple', domains: ['apple.com', 'icloud.com', 'me.com', 'apple.news'] },
  { token: 'icloud', name: 'iCloud', domains: ['icloud.com', 'apple.com'] },
  { token: 'amazon', name: 'Amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.in', 'amazon.co.jp', 'amazon.com.au', 'amazon.nl', 'amazon.ae', 'amazon.sa', 'amazon.com.br', 'amazon.com.mx', 'amazon.sg', 'amazon.pl', 'amazon.se', 'amazonpay.com', 'primevideo.com'] },
  { token: 'aws', name: 'AWS', domains: ['aws.amazon.com', 'amazon.com', 'awsapps.com', 'signin.aws'] },
  { token: 'netflix', name: 'Netflix', domains: ['netflix.com'] },
  { token: 'facebook', name: 'Facebook', domains: ['facebook.com', 'meta.com', 'messenger.com', 'fb.com'] },
  { token: 'instagram', name: 'Instagram', domains: ['instagram.com'] },
  { token: 'whatsapp', name: 'WhatsApp', domains: ['whatsapp.com'] },
  { token: 'linkedin', name: 'LinkedIn', domains: ['linkedin.com'] },
  { token: 'twitter', name: 'X (Twitter)', domains: ['x.com', 'twitter.com'] },
  { token: 'github', name: 'GitHub', domains: ['github.com'] },
  { token: 'gitlab', name: 'GitLab', domains: ['gitlab.com'] },
  { token: 'dropbox', name: 'Dropbox', domains: ['dropbox.com'] },
  { token: 'slack', name: 'Slack', domains: ['slack.com'] },
  { token: 'zoom', name: 'Zoom', domains: ['zoom.us', 'zoom.com'] },
  { token: 'docusign', name: 'DocuSign', domains: ['docusign.com', 'docusign.net'] },
  { token: 'adobe', name: 'Adobe', domains: ['adobe.com'] },
  { token: 'stripe', name: 'Stripe', domains: ['stripe.com'] },
  { token: 'coinbase', name: 'Coinbase', domains: ['coinbase.com'] },
  { token: 'binance', name: 'Binance', domains: ['binance.com', 'binance.us'] },
  { token: 'metamask', name: 'MetaMask', domains: ['metamask.io'] },
  { token: 'kraken', name: 'Kraken', domains: ['kraken.com'] },
  { token: 'chase', name: 'Chase', domains: ['chase.com'] },
  { token: 'wellsfargo', name: 'Wells Fargo', domains: ['wellsfargo.com'] },
  { token: 'hsbc', name: 'HSBC', domains: ['hsbc.com', 'hsbc.co.uk'] },
  { token: 'barclays', name: 'Barclays', domains: ['barclays.co.uk', 'barclays.com'] },
  { token: 'citibank', name: 'Citi', domains: ['citi.com', 'citibank.com'] },
  { token: 'revolut', name: 'Revolut', domains: ['revolut.com'] },
  { token: 'wise', name: 'Wise', domains: ['wise.com'] },
  { token: 'westernunion', name: 'Western Union', domains: ['westernunion.com'] },
  { token: 'dhl', name: 'DHL', domains: ['dhl.com', 'dhl.de'] },
  { token: 'fedex', name: 'FedEx', domains: ['fedex.com'] },
  { token: 'ups', name: 'UPS', domains: ['ups.com'] },
  { token: 'usps', name: 'USPS', domains: ['usps.com'] },
  { token: 'royalmail', name: 'Royal Mail', domains: ['royalmail.com'] },
  // Commonly phished, not (yet) in the page-signal lexicon.
  { token: 'bankofamerica', name: 'Bank of America', domains: ['bankofamerica.com'] },
  { token: 'steam', name: 'Steam', domains: ['steampowered.com', 'steamcommunity.com'] },
  { token: 'ebay', name: 'eBay', domains: ['ebay.com', 'ebay.co.uk', 'ebay.de'] },
  { token: 'spotify', name: 'Spotify', domains: ['spotify.com'] },
  { token: 'discord', name: 'Discord', domains: ['discord.com', 'discord.gg', 'discordapp.com'] },
  { token: 'roblox', name: 'Roblox', domains: ['roblox.com'] },
  { token: 'walmart', name: 'Walmart', domains: ['walmart.com'] },
  { token: 'americanexpress', name: 'American Express', domains: ['americanexpress.com'] },
  { token: 'booking', name: 'Booking.com', domains: ['booking.com'] },
  // Regional telecoms & service providers frequently targeted by SMS/phishing lures
  { token: 'maxis', name: 'Maxis', domains: ['maxis.com.my', 'maxis.my'] },
  { token: 'celcom', name: 'CelcomDigi', domains: ['celcomdigi.com', 'celcom.com.my'] },
  { token: 'digi', name: 'Digi', domains: ['digi.com.my'] },
  { token: 'unifi', name: 'Unifi', domains: ['unifi.com.my', 'tm.com.my'] },
  { token: 'singtel', name: 'Singtel', domains: ['singtel.com'] },
  // LATAM financial institutions & loyalty programs frequently targeted
  { token: 'dinersclub', name: 'Diners Club', domains: ['dinersclub.com', 'dinersclub.com.ec', 'dinersclubus.com'] },
  { token: 'clubmiles', name: 'Club Miles', domains: ['clubmiles.com.ec', 'clubmiles.ec'] },
  { token: 'pichincha', name: 'Banco Pichincha', domains: ['pichincha.com'] },
  { token: 'bancoguayaquil', name: 'Banco Guayaquil', domains: ['bancoguayaquil.com'] },
  { token: 'produbanco', name: 'Produbanco', domains: ['produbanco.com.ec', 'produbanco.com'] },
  { token: 'mercadopago', name: 'Mercado Pago', domains: ['mercadopago.com', 'mercadopago.com.ar', 'mercadopago.com.br', 'mercadopago.com.mx'] },
  { token: 'mercadolibre', name: 'Mercado Libre', domains: ['mercadolibre.com', 'mercadolibre.com.ar', 'mercadolibre.com.br', 'mercadolibre.com.mx', 'mercadolibre.com.ec'] },
  { token: 'bbva', name: 'BBVA', domains: ['bbva.com', 'bbva.es', 'bbva.mx', 'bbva.com.ar'] },
  { token: 'santander', name: 'Santander', domains: ['santander.com', 'santander.es', 'santander.com.mx', 'santander.com.br', 'santander.co.uk'] },
];

/** Catalog + remotely supplied brands (validated). */
export function mergeExtraBrands(extra: readonly { token?: unknown; name?: unknown; domains?: unknown }[] | undefined): CatalogBrand[] {
  const out: CatalogBrand[] = [...BRAND_CATALOG];
  const seen = new Set(out.map((b) => b.token));
  for (const e of (extra || []).slice(0, 200)) {
    const token = typeof e.token === 'string' ? e.token.toLowerCase().replace(/[^a-z0-9]/g, '') : '';
    const domains = Array.isArray(e.domains)
      ? e.domains
          .filter((d): d is string => typeof d === 'string')
          .map((d) => d.trim().toLowerCase().replace(/^www\./, ''))
          .filter((d) => /^(?=.{1,253}$)[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d))
          .slice(0, 30)
      : [];
    if (token.length < 3 || !domains.length || seen.has(token)) continue;
    seen.add(token);
    out.push({ token, name: typeof e.name === 'string' ? e.name.slice(0, 60) : token, domains });
  }
  return out;
}

/** Every registrable domain in the catalog. */
export function catalogDomains(brands: readonly CatalogBrand[] = BRAND_CATALOG): string[] {
  return Array.from(new Set(brands.flatMap((b) => b.domains)));
}

/** True when `reg` (a registrable domain or host) belongs to the brand. */
export function brandOwnsHost(brand: CatalogBrand, host: string): boolean {
  const h = host.toLowerCase();
  return brand.domains.some((d) => h === d || h.endsWith(`.${d}`));
}
