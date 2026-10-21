export const EMAIL_BADGE_SELECTOR = '[data-xorapass-badge]';

/** Remove inline email warnings before a webmail DOM is rescanned. */
export function removeEmailBadges(root: ParentNode): number {
  let removed = 0;
  root.querySelectorAll(EMAIL_BADGE_SELECTOR).forEach((badge) => {
    badge.remove();
    removed++;
  });
  return removed;
}
