// XoraPass tracker list: domains of widely used third-party advertising,
// analytics and cross-site tracking services, grouped by company.
//
// Curated by XoraPass from the services' own public documentation (domain
// names are facts, not copyrighted material), so it ships without the
// licence obligations of third-party lists. Used for:
//   • recognition — which trackers a page loads (Site Scanner)
//   • blocking   — declarativeNetRequest rules when "Block trackers" is on
//   • cookie labelling in the cookie viewer
//
// Only THIRD-party requests are ever blocked, so a company's own site keeps
// working (e.g. google.com still loads its own analytics).

export interface TrackerCompany {
  company: string;
  category: 'advertising' | 'analytics' | 'social' | 'session_replay' | 'fingerprinting';
  domains: string[];
}

export const TRACKER_COMPANIES: readonly TrackerCompany[] = [
  { company: 'Google', category: 'advertising', domains: ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'googletagservices.com', 'adservice.google.com', 'pagead2.googlesyndication.com', 'app-measurement.com'] },
  { company: 'Google', category: 'analytics', domains: ['google-analytics.com', 'analytics.google.com', 'googletagmanager.com', 'ssl.google-analytics.com'] },
  { company: 'Meta', category: 'social', domains: ['connect.facebook.net', 'facebook.net', 'pixel.facebook.com', 'an.facebook.com'] },
  { company: 'Microsoft', category: 'advertising', domains: ['bat.bing.com', 'ads.microsoft.com', 'clarity.ms', 'c.clarity.ms'] },
  { company: 'Amazon', category: 'advertising', domains: ['amazon-adsystem.com', 'assoc-amazon.com'] },
  { company: 'X (Twitter)', category: 'social', domains: ['ads-twitter.com', 'static.ads-twitter.com', 'analytics.twitter.com', 't.co'] },
  { company: 'LinkedIn', category: 'social', domains: ['snap.licdn.com', 'px.ads.linkedin.com', 'ads.linkedin.com'] },
  { company: 'TikTok', category: 'social', domains: ['analytics.tiktok.com', 'ads.tiktok.com', 'business-api.tiktok.com'] },
  { company: 'Pinterest', category: 'social', domains: ['ct.pinterest.com', 'analytics.pinterest.com'] },
  { company: 'Snap', category: 'social', domains: ['sc-static.net', 'tr.snapchat.com'] },
  { company: 'Reddit', category: 'social', domains: ['alb.reddit.com', 'events.redditmedia.com'] },
  { company: 'Criteo', category: 'advertising', domains: ['criteo.com', 'criteo.net'] },
  { company: 'Taboola', category: 'advertising', domains: ['taboola.com', 'taboolasyndication.com'] },
  { company: 'Outbrain', category: 'advertising', domains: ['outbrain.com', 'outbrainimg.com'] },
  { company: 'The Trade Desk', category: 'advertising', domains: ['adsrvr.org'] },
  { company: 'Xandr (AppNexus)', category: 'advertising', domains: ['adnxs.com', 'adnxs-simple.com'] },
  { company: 'Magnite / Rubicon', category: 'advertising', domains: ['rubiconproject.com', 'magnite.com'] },
  { company: 'PubMatic', category: 'advertising', domains: ['pubmatic.com'] },
  { company: 'OpenX', category: 'advertising', domains: ['openx.net', 'openx.com'] },
  { company: 'Index Exchange', category: 'advertising', domains: ['casalemedia.com', 'indexww.com'] },
  { company: 'Quantcast', category: 'advertising', domains: ['quantserve.com', 'quantcount.com', 'quantcast.com'] },
  { company: 'LiveRamp', category: 'advertising', domains: ['rlcdn.com', 'pippio.com', 'liveramp.com'] },
  { company: 'Lotame', category: 'advertising', domains: ['crwdcntrl.net'] },
  { company: 'MediaMath', category: 'advertising', domains: ['mathtag.com'] },
  { company: 'Yahoo Advertising', category: 'advertising', domains: ['ads.yahoo.com', 'analytics.yahoo.com', 'advertising.com'] },
  { company: 'Adform', category: 'advertising', domains: ['adform.net', 'adformdsp.net'] },
  { company: 'Smart AdServer', category: 'advertising', domains: ['smartadserver.com'] },
  { company: 'Sovrn', category: 'advertising', domains: ['lijit.com', 'sovrn.com'] },
  { company: 'Media.net', category: 'advertising', domains: ['media.net'] },
  { company: 'Moat (Oracle)', category: 'advertising', domains: ['moatads.com'] },
  { company: 'Integral Ad Science', category: 'advertising', domains: ['adsafeprotected.com'] },
  { company: 'DoubleVerify', category: 'advertising', domains: ['doubleverify.com'] },
  { company: 'Comscore', category: 'analytics', domains: ['scorecardresearch.com', 'comscore.com'] },
  { company: 'Chartbeat', category: 'analytics', domains: ['chartbeat.com', 'chartbeat.net'] },
  { company: 'Adobe', category: 'analytics', domains: ['omtrdc.net', 'demdex.net', '2o7.net', 'everesttech.net'] },
  { company: 'Segment', category: 'analytics', domains: ['segment.io', 'segment.com', 'cdn.segment.com'] },
  { company: 'Mixpanel', category: 'analytics', domains: ['mixpanel.com', 'mxpnl.com'] },
  { company: 'Amplitude', category: 'analytics', domains: ['amplitude.com'] },
  { company: 'Heap', category: 'analytics', domains: ['heapanalytics.com', 'heap-api.com'] },
  { company: 'HubSpot', category: 'analytics', domains: ['hs-analytics.net', 'hs-scripts.com', 'hsadspixel.net', 'hscollectedforms.net'] },
  { company: 'Kissmetrics', category: 'analytics', domains: ['kissmetrics.com', 'kissmetrics.io'] },
  { company: 'New Relic', category: 'analytics', domains: ['nr-data.net'] },
  { company: 'Yandex', category: 'analytics', domains: ['mc.yandex.ru', 'mc.yandex.com'] },
  { company: 'Hotjar', category: 'session_replay', domains: ['hotjar.com', 'hotjar.io'] },
  { company: 'FullStory', category: 'session_replay', domains: ['fullstory.com'] },
  { company: 'Mouseflow', category: 'session_replay', domains: ['mouseflow.com'] },
  { company: 'Smartlook', category: 'session_replay', domains: ['smartlook.com'] },
  { company: 'Lucky Orange', category: 'session_replay', domains: ['luckyorange.com', 'luckyorange.net'] },
  { company: 'Inspectlet', category: 'session_replay', domains: ['inspectlet.com'] },
  { company: 'Crazy Egg', category: 'session_replay', domains: ['crazyegg.com'] },
  { company: 'FingerprintJS', category: 'fingerprinting', domains: ['fpjs.io', 'fptls.com', 'api.fpjs.io'] },
  { company: 'ThreatMetrix', category: 'fingerprinting', domains: ['online-metrix.net'] },
  { company: 'AddThis', category: 'social', domains: ['addthis.com', 'addthisedge.com'] },
  { company: 'ShareThis', category: 'social', domains: ['sharethis.com'] },
];

/** Flat domain → company index. */
export const TRACKER_DOMAINS: ReadonlyMap<string, TrackerCompany> = (() => {
  const m = new Map<string, TrackerCompany>();
  for (const c of TRACKER_COMPANIES) for (const d of c.domains) m.set(d, c);
  return m;
})();

/** Returns the tracker company for a hostname (exact or parent-domain match). */
export function trackerFor(host: string): TrackerCompany | null {
  let h = (host || '').toLowerCase().replace(/^www\./, '');
  while (h.includes('.')) {
    const hit = TRACKER_DOMAINS.get(h);
    if (hit) return hit;
    h = h.slice(h.indexOf('.') + 1);
  }
  return null;
}

/** Domains for the declarativeNetRequest block rule. */
export function blockableTrackerDomains(): string[] {
  // t.co is also X's link shortener used for navigation — never block it.
  return Array.from(TRACKER_DOMAINS.keys()).filter((d) => d !== 't.co');
}

const TRACKING_COOKIE_PATTERNS: ReadonlyArray<[RegExp, string]> = [
  [/^_ga(_.*)?$|^_gid$|^_gat/, 'Google Analytics'],
  [/^_gcl_/, 'Google Ads'],
  [/^_fbp$|^_fbc$/, 'Meta Pixel'],
  [/^_uet(sid|vid)$/, 'Microsoft Ads'],
  [/^_clck$|^_clsk$/, 'Microsoft Clarity'],
  [/^_hj/, 'Hotjar'],
  [/^__hs|^hubspotutk$/, 'HubSpot'],
  [/^ajs_(user|anonymous)_id$/, 'Segment'],
  [/^mp_.*_mixpanel$/, 'Mixpanel'],
  [/^amp_/, 'Amplitude'],
  [/^_ttp$|^tt_/, 'TikTok'],
  [/^_pin_unauth$|^_pinterest_/, 'Pinterest'],
  [/^li_(fat_id|sugr)$|^lidc$|^bcookie$/, 'LinkedIn'],
  [/^_scid/, 'Snap'],
  [/^IDE$|^DSID$|^test_cookie$/, 'Google (DoubleClick)'],
  [/^_rdt_uuid$/, 'Reddit'],
  [/^s_(cc|sq|vi|fid)$|^AMCV_/, 'Adobe Analytics'],
];

/** Labels a cookie NAME as a known tracker cookie (values are never read). */
export function trackingCookieOwner(name: string): string | null {
  for (const [re, owner] of TRACKING_COOKIE_PATTERNS) if (re.test(name)) return owner;
  return null;
}
