import React from 'react';

/**
 * XoraPass brand assets, mirroring apps/web src/components/Logo.tsx so the
 * extension and the web vault present the same lockup.
 *
 * The PNGs live in public/ and are copied to the extension root at build time,
 * so a root-relative src resolves to chrome-extension://<id>/<file>.
 *
 * - LogoIcon: square X-shield mark, transparent background — safe on any theme.
 * - LogoHorizontal: mark + wordmark; automatically displays the light (teal wordmark)
 *   or dark (crisp white wordmark) logo variant depending on theme or isDark prop.
 */
export const LogoIcon: React.FC<{ className?: string }> = ({ className = 'w-8 h-8' }) => (
  <img
    src="/xorapass_logo_mark.png"
    alt="XoraPass"
    className={`${className} object-contain select-none`}
    draggable={false}
  />
);

export const LogoHorizontal: React.FC<{ className?: string; isDark?: boolean }> = ({
  className = 'h-10 w-auto',
  isDark,
}) => {
  if (isDark !== undefined) {
    return (
      <img
        src={isDark ? '/xorapass_logo_horizontal_dark.png' : '/xorapass_logo_horizontal.png'}
        alt="XoraPass"
        className={`${className} object-contain select-none`}
        draggable={false}
      />
    );
  }

  return (
    <>
      <img
        src="/xorapass_logo_horizontal.png"
        alt="XoraPass"
        className={`${className} object-contain select-none dark:hidden`}
        draggable={false}
      />
      <img
        src="/xorapass_logo_horizontal_dark.png"
        alt="XoraPass"
        className={`${className} object-contain select-none hidden dark:block`}
        draggable={false}
      />
    </>
  );
};
