// Checkout Guard sub-frame probe.
//
// Real checkouts put the card fields in a cross-origin iframe (Stripe
// Elements, Braintree Hosted Fields, Adyen, ...), which the main content
// script — top frame only — can never see. This deliberately tiny script runs
// in every SUB-frame, and does exactly one thing: if the frame contains card
// inputs, it tells the background once, which relays it to the top frame's
// content script. That script decides whether the TOP page is suspicious and
// shows the banner there — the iframe's own origin (the payment processor)
// says nothing about the merchant page embedding it.
//
// It never reads input VALUES — only the same attributes cardGuard.ts scores.
// Built as its own self-contained IIFE (vite --mode cardframe).

import browser from 'webextension-polyfill';
import { assessPaymentInputs } from './cardGuard';
import type { FieldAttrs } from './fieldHeuristics';

(() => {
  if (window === window.top) return;

  let reported = false;
  let observer: MutationObserver | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;

  function attrsOf(el: HTMLInputElement): FieldAttrs {
    const label = el.labels && el.labels[0] ? el.labels[0].textContent : null;
    return {
      type: el.type,
      autocomplete: el.getAttribute('autocomplete'),
      name: el.name,
      id: el.id,
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
      labelText: label,
    };
  }

  function scan(): void {
    if (reported) return;
    const inputs = Array.from(document.querySelectorAll('input')) as HTMLInputElement[];
    if (inputs.length === 0) return;
    const { hasCardNumber, hasCvv, hasExpiry } = assessPaymentInputs(inputs.map(attrsOf));
    // A split-field processor frame often holds just ONE field (only the card
    // number, or only the CVC), so any card field counts here.
    if (!hasCardNumber && !hasCvv && !hasExpiry) return;
    reported = true;
    observer?.disconnect();
    browser.runtime.sendMessage({ type: 'CARD_FIELDS_IN_FRAME' }).catch(() => {});
  }

  scan();
  if (!reported && document.documentElement) {
    observer = new MutationObserver(() => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        scan();
      }, 400);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    // Payment fields render within seconds of load; don't watch forever.
    setTimeout(() => observer?.disconnect(), 30_000);
  }
})();
