import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'path';

// https://vite.dev/config/
//
// Two build passes (run in sequence by `npm run build`):
//   - default mode: popup + background as ES modules (they load as modules, so
//     sharing chunks such as webextension-polyfill is fine).
//   - `--mode content`: the content script as a self-contained IIFE. MV3 content
//     scripts run as classic scripts and CANNOT use ES `import`, so it must be
//     bundled with all dependencies (incl. webextension-polyfill) inlined and no
//     external chunk references.
export default defineConfig(({ mode }) => {
  const plugins = [react(), tailwindcss()];

  if (mode === 'content') {
    return {
      plugins,
      build: {
        target: 'esnext',
        outDir: 'dist',
        emptyOutDir: false, // keep popup/background/assets from the first pass
        rollupOptions: {
          input: { content: resolve(__dirname, 'src/content/content.ts') },
          output: {
            format: 'iife',
            inlineDynamicImports: true,
            entryFileNames: '[name].js',
          },
        },
      },
      esbuild: { target: 'esnext' },
    };
  }

  return {
    plugins,
    build: {
      target: 'esnext',
      outDir: 'dist',
      emptyOutDir: true,
      rollupOptions: {
        input: {
          popup: resolve(__dirname, 'popup.html'),
          background: resolve(__dirname, 'src/background/background.ts'),
        },
        output: {
          entryFileNames: '[name].js',
          chunkFileNames: 'assets/[name].js',
          assetFileNames: 'assets/[name].[ext]',
        },
      },
    },
    esbuild: { target: 'esnext' },
  };
});
