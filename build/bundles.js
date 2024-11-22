import esbuild from 'esbuild';
import browserConfig from './esbuild-browser-config.cjs';

// esm polyfilled bundle for browser
esbuild.build({
  ...browserConfig,
  metafile : true,
  outfile  : 'dist/browser/index.mjs',
});

// iife polyfilled bundle for browser
esbuild.build({
  ...browserConfig,
  format     : 'iife',
  globalName : 'DidBtc1Js',
  outfile    : 'dist/browser/index.js',
});