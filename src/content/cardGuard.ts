// Pure field heuristics for payment card and checkout forms.
// Free of DOM access so it can be cleanly unit-tested in node / Vitest.

import type { FieldAttrs } from './fieldHeuristics';

const CARD_NUMBER_HINT = /card[\s\-_]?num(ber)?|cc[\s\-_]?num|credit[\s\-_]?card|pan|card[\s\-_]?no|account[\s\-_]?num(ber)?/i;
const CVV_HINT = /cvv|cvc|csc|security[\s\-_]?code|verification[\s\-_]?code|card[\s\-_]?code/i;
const EXPIRY_HINT = /expir(y|ation)|exp[\s\-_]?date|card[\s\-_]?exp|cc[\s\-_]?exp/i;

// Words that indicate non-card inputs even if matching loose substring hints
const NEGATIVE_HINT = /search|query|coupon|promo|gift[\s\-_]?card|voucher|discount|zip|postal|phone|ssn/i;

/**
 * Checks if an input matches credit card number characteristics.
 */
export function looksLikeCardNumber(attrs: FieldAttrs): boolean {
  const type = (attrs.type || 'text').toLowerCase();
  if (type === 'password' || type === 'hidden' || type === 'submit') return false;

  const ac = (attrs.autocomplete || '').toLowerCase();
  if (ac.includes('cc-number')) return true;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel, attrs.labelText]
    .filter(Boolean)
    .join(' ');

  if (NEGATIVE_HINT.test(hints)) return false;
  return CARD_NUMBER_HINT.test(hints);
}

/**
 * Checks if an input matches CVV / CVC / security code characteristics.
 */
export function looksLikeCvv(attrs: FieldAttrs): boolean {
  const type = (attrs.type || 'hidden').toLowerCase();
  if (type === 'submit') return false;

  const ac = (attrs.autocomplete || '').toLowerCase();
  if (ac.includes('cc-csc')) return true;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel, attrs.labelText]
    .filter(Boolean)
    .join(' ');

  if (NEGATIVE_HINT.test(hints)) return false;
  return CVV_HINT.test(hints);
}

/**
 * Checks if an input matches card expiration date characteristics.
 */
export function looksLikeCardExpiry(attrs: FieldAttrs): boolean {
  const type = (attrs.type || 'text').toLowerCase();
  if (type === 'hidden' || type === 'submit') return false;

  const ac = (attrs.autocomplete || '').toLowerCase();
  if (ac.includes('cc-exp')) return true;

  const hints = [attrs.name, attrs.id, attrs.placeholder, attrs.ariaLabel, attrs.labelText]
    .filter(Boolean)
    .join(' ');

  if (NEGATIVE_HINT.test(hints)) return false;
  return EXPIRY_HINT.test(hints);
}

export interface PaymentFormAssessment {
  hasCardNumber: boolean;
  hasCvv: boolean;
  hasExpiry: boolean;
  isPaymentForm: boolean;
}

/**
 * Evaluates whether a set of form input attributes collectively constitutes a payment form.
 */
export function assessPaymentInputs(inputs: FieldAttrs[]): PaymentFormAssessment {
  let hasCardNumber = false;
  let hasCvv = false;
  let hasExpiry = false;

  for (const input of inputs) {
    if (looksLikeCardNumber(input)) hasCardNumber = true;
    if (looksLikeCvv(input)) hasCvv = true;
    if (looksLikeCardExpiry(input)) hasExpiry = true;
  }

  // A form is considered a payment form if it has a card number field,
  // or a combination of CVV + Expiry (common in split iframes).
  const isPaymentForm = hasCardNumber || (hasCvv && hasExpiry);

  return {
    hasCardNumber,
    hasCvv,
    hasExpiry,
    isPaymentForm,
  };
}
