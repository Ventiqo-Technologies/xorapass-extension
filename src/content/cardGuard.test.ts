import { describe, it, expect } from 'vitest';
import {
  looksLikeCardNumber,
  looksLikeCvv,
  looksLikeCardExpiry,
  assessPaymentInputs,
} from './cardGuard';

describe('cardGuard heuristics', () => {
  describe('looksLikeCardNumber', () => {
    it('detects standard autocomplete cc-number', () => {
      expect(looksLikeCardNumber({ autocomplete: 'cc-number' })).toBe(true);
      expect(looksLikeCardNumber({ autocomplete: 'section-billing cc-number' })).toBe(true);
    });

    it('detects name / id hints for card number', () => {
      expect(looksLikeCardNumber({ name: 'cardNumber' })).toBe(true);
      expect(looksLikeCardNumber({ id: 'cc_num' })).toBe(true);
      expect(looksLikeCardNumber({ placeholder: 'Credit Card Number' })).toBe(true);
      expect(looksLikeCardNumber({ ariaLabel: 'Enter Card Number' })).toBe(true);
    });

    it('rejects password, hidden, or negative hints', () => {
      expect(looksLikeCardNumber({ type: 'password', name: 'cardNumber' })).toBe(false);
      expect(looksLikeCardNumber({ type: 'hidden', name: 'cardNumber' })).toBe(false);
      expect(looksLikeCardNumber({ name: 'giftCardNumber' })).toBe(false);
      expect(looksLikeCardNumber({ placeholder: 'Search card catalog' })).toBe(false);
      expect(looksLikeCardNumber({ name: 'zipcode' })).toBe(false);
    });
  });

  describe('looksLikeCvv', () => {
    it('detects autocomplete cc-csc', () => {
      expect(looksLikeCvv({ autocomplete: 'cc-csc' })).toBe(true);
    });

    it('detects cvv/cvc hints', () => {
      expect(looksLikeCvv({ name: 'cvv' })).toBe(true);
      expect(looksLikeCvv({ id: 'card-cvc' })).toBe(true);
      expect(looksLikeCvv({ placeholder: 'Security code' })).toBe(true);
      expect(looksLikeCvv({ ariaLabel: 'Card verification code' })).toBe(true);
    });

    it('rejects coupon / promo code fields', () => {
      expect(looksLikeCvv({ name: 'couponCode', placeholder: 'Enter promo code' })).toBe(false);
    });
  });

  describe('looksLikeCardExpiry', () => {
    it('detects autocomplete cc-exp', () => {
      expect(looksLikeCardExpiry({ autocomplete: 'cc-exp' })).toBe(true);
      expect(looksLikeCardExpiry({ autocomplete: 'cc-exp-month' })).toBe(true);
    });

    it('detects expiry hints', () => {
      expect(looksLikeCardExpiry({ name: 'cardExpiry' })).toBe(true);
      expect(looksLikeCardExpiry({ id: 'exp_date' })).toBe(true);
      expect(looksLikeCardExpiry({ placeholder: 'MM / YY' })).toBe(false); // only placeholder without hint doesn't false-trigger unless hints say exp
      expect(looksLikeCardExpiry({ placeholder: 'Expiration Date (MM/YY)' })).toBe(true);
    });
  });

  describe('assessPaymentInputs', () => {
    it('identifies standard checkout form', () => {
      const inputs = [
        { name: 'customer_name', type: 'text' },
        { name: 'cardNumber', type: 'text', autocomplete: 'cc-number' },
        { name: 'cardExp', type: 'text', autocomplete: 'cc-exp' },
        { name: 'cardCvv', type: 'text', autocomplete: 'cc-csc' },
      ];

      const assessment = assessPaymentInputs(inputs);
      expect(assessment.isPaymentForm).toBe(true);
      expect(assessment.hasCardNumber).toBe(true);
      expect(assessment.hasExpiry).toBe(true);
      expect(assessment.hasCvv).toBe(true);
    });

    it('identifies split iframe containing CVV + Expiry', () => {
      const inputs = [
        { name: 'cardExp', type: 'text', autocomplete: 'cc-exp' },
        { name: 'cvv', type: 'text', autocomplete: 'cc-csc' },
      ];

      const assessment = assessPaymentInputs(inputs);
      expect(assessment.isPaymentForm).toBe(true);
      expect(assessment.hasCardNumber).toBe(false);
      expect(assessment.hasExpiry).toBe(true);
      expect(assessment.hasCvv).toBe(true);
    });

    it('rejects ordinary login or contact forms', () => {
      const inputs = [
        { name: 'username', type: 'text', autocomplete: 'username' },
        { name: 'password', type: 'password', autocomplete: 'current-password' },
      ];

      const assessment = assessPaymentInputs(inputs);
      expect(assessment.isPaymentForm).toBe(false);
      expect(assessment.hasCardNumber).toBe(false);
    });
  });
});
