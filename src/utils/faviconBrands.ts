// Reference favicon hashes for commonly impersonated brands (dHash, see
// faviconHash.ts). Generated 2026-09-18 from each brand's own favicon, hashed
// in Chromium with the same code the content script uses. Regenerate with
// scripts/gen-favicon-brands.mjs when a brand changes its icon.
// Brands must be tokens of the server's BrandLexicon.

import type { FaviconBrand } from './faviconHash';

export const FAVICON_BRANDS: readonly FaviconBrand[] = [
  { brand: "paypal", domains: ["paypal.com"], hashes: ["00707c78e0c0f030"] },
  { brand: "microsoft", domains: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "bing.com", "azure.com", "msauth.net", "msftauth.net", "microsoft365.com"], hashes: ["0909090808080808"] },
  { brand: "outlook", domains: ["outlook.com", "live.com", "office.com", "microsoft.com", "microsoft365.com"], hashes: ["3020305050346761"] },
  { brand: "google", domains: ["google.com", "gmail.com", "youtube.com"], hashes: ["d4f0c9dcdeccf0d4"] },
  { brand: "apple", domains: ["apple.com", "icloud.com"], hashes: ["cc9a7961617982cc"] },
  { brand: "icloud", domains: ["icloud.com", "apple.com"], hashes: ["a23979fcfefc7daa"] },
  { brand: "amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amazon.com.au"], hashes: ["c08000610f0080c0"] },
  { brand: "netflix", domains: ["netflix.com"], hashes: ["4c4c444c4c4c4c4c"] },
  { brand: "facebook", domains: ["facebook.com", "meta.com", "messenger.com"], hashes: ["f0e68e8c868eccc8"] },
  { brand: "instagram", domains: ["instagram.com"], hashes: ["c03b4955554d3f9e"] },
  { brand: "whatsapp", domains: ["whatsapp.com"], hashes: ["f0f0d090d6c4f030"] },
  { brand: "linkedin", domains: ["linkedin.com"], hashes: ["c0b0b6a6aaaaaac0"] },
  { brand: "github", domains: ["github.com"], hashes: ["f0aa8a03038e8ccc"] },
  { brand: "dropbox", domains: ["dropbox.com"], hashes: ["aa923392138e8ca0"] },
  { brand: "docusign", domains: ["docusign.com", "docusign.net"], hashes: ["0038707070786000"] },
  { brand: "adobe", domains: ["adobe.com"], hashes: ["307068e8cccca686"] },
  { brand: "coinbase", domains: ["coinbase.com"], hashes: ["30f8cc8686ccf830"] },
  { brand: "binance", domains: ["binance.com"], hashes: ["3078ccb3b3cc7830"] },
  { brand: "metamask", domains: ["metamask.io"], hashes: ["878e8e8eecaa96b2"] },
  { brand: "chase", domains: ["chase.com"], hashes: ["f0f09e868686e2f0"] },
  { brand: "wellsfargo", domains: ["wellsfargo.com"], hashes: ["00a0bc31d7657500"] },
  { brand: "dhl", domains: ["dhl.com", "dhl.de"], hashes: ["00003368d4230000"] },
  { brand: "ups", domains: ["ups.com"], hashes: ["f8feccd2d4a8e870"] },
  { brand: "usps", domains: ["usps.com"], hashes: ["c0fe3a39673efaaa"] },
  { brand: "stripe", domains: ["stripe.com"], hashes: ["c0020206061e20c0"] },
  { brand: "slack", domains: ["slack.com"], hashes: ["6868898aac2c6068"] },
  { brand: "zoom", domains: ["zoom.us", "zoom.com"], hashes: ["f0c0b22929b8c0f0"] },
  { brand: "twitter", domains: ["x.com", "twitter.com"], hashes: ["00332e140e336100"] },
  { brand: "revolut", domains: ["revolut.com"], hashes: ["60684c5c50584c4c"] },
];
