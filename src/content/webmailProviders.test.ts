import { describe, expect, it } from 'vitest';
import { parseOutlookSender } from './webmailProviders';

describe('Outlook header sender selection', () => {
  it('never uses recipients following the actual sender', () => {
    expect(parseOutlookSender('Alert Manager\n<alerts@example.com>\nTo: Recipient One; Recipient Two <recipient@example.net>'))
      .toEqual({ senderName: 'Alert Manager', senderEmail: 'alerts@example.com' });
  });
  it.each(['To: Recipient <recipient@example.net>', 'Cc: Recipient <recipient@example.net>', 'Bcc: Recipient <recipient@example.net>', 'Alert Manager\nTo: recipient@example.net'])('does not invent a sender from %s', text => {
    expect(parseOutlookSender(text).senderEmail).toBe('');
  });
  it('rejects ambiguous headers', () => {
    expect(parseOutlookSender('one@example.com two@example.com').senderEmail).toBe('');
  });
  it('reads explicitly labelled sender headers', () => {
    expect(parseOutlookSender('From: Alice <alice@example.com>')).toEqual({ senderName: 'Alice', senderEmail: 'alice@example.com' });
  });
});
