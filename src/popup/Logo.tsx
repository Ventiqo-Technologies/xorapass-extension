import React from 'react';

/**
 * XoraPass brand assets, mirroring apps/web src/components/Logo.tsx so the
 * extension and the web vault present the same lockup.
 *
 * The PNGs live in public/ and are copied to the extension root at build time,
 * so a root-relative src resolves to chrome-extension://<id>/<file>.
 *
 * - LogoIcon: square X-shield mark, transparent background — safe on any theme.
 * - LogoHorizontal: mark + wordmark; the wordmark is dark teal, so it needs a
 *   light surface behind it.
 */
export const LogoIcon: React.FC<{ className?: string }> = ({ className = 'w-8 h-8' }) => (
  <img
    src="/xorapass_logo_mark.png"
    alt="XoraPass"
    className={`${className} object-contain select-none`}
    draggable={false}
  />
);

export const LogoHorizontal: React.FC<{ className?: string }> = ({ className = 'h-10 w-auto' }) => (
  <img
    src="/xorapass_logo_horizontal.png"
    alt="XoraPass"
    className={`${className} object-contain select-none`}
    draggable={false}
  />
);
