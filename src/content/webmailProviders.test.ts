import { describe, expect, it } from 'vitest';
import { isGmailFullMessagePage, parseGmailFullMessageHeader, parseOutlookSender } from './webmailProviders';

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

describe('Gmail standalone full-message view', () => {
  it('recognizes only Gmail legacy full-message URLs', () => {
    expect(isGmailFullMessagePage('mail.google.com', '?view=lg&permmsgid=msg-f:123')).toBe(true);
    expect(isGmailFullMessagePage('mail.google.com', '?view=cv&permmsgid=msg-f:123')).toBe(false);
    expect(isGmailFullMessagePage('evil.example', '?view=lg&permmsgid=msg-f:123')).toBe(false);
  });

  it('extracts the sender and subject without treating recipients as the sender', () => {
    expect(parseGmailFullMessageHeader([
      'Subject: [XoraPass TEST] Simulated phishing email',
      'Trishane Mirando <trishane@trifinix.com>',
      'To: Trishane Mirando <trishane@gmail.com>',
      '',
      'Body:',
      'Reply with your password and verification code.',
    ].join('\n'))).toEqual({
      senderName: 'Trishane Mirando',
      senderEmail: 'trishane@trifinix.com',
      subject: '[XoraPass TEST] Simulated phishing email',
      senderLookupComplete: true,
    });
  });

  it('handles the account header when Gmail collapses visual line breaks', () => {
    expect(parseGmailFullMessageHeader(
      'Gmail Trishane Mirando <trishane@gmail.com> Subject: [XoraPass TEST] Lookalike link Trishane Mirando <trishane@trifinix.com> To: Trishane Mirando <trishane@gmail.com>'
    )).toMatchObject({
      senderName: '',
      senderEmail: 'trishane@trifinix.com',
      senderLookupComplete: true,
    });
  });
});
