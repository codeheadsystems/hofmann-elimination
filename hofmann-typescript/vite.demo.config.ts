/**
 * Vite config for demo.html — dev server and production build.
 *
 * Dev server proxies /opaque, /oprf and /api to the hofmann-server running on
 * localhost:8080, avoiding CORS issues when the demo page is served from a
 * different port.
 *
 * Production build (npm run build:demo) outputs to dist-demo/ for the Docker
 * demo environment where nginx handles the reverse proxy.
 *
 * Usage:
 *   npm run demo          # start dev server
 *   npm run build:demo    # build static bundle for Docker
 */
import { resolve } from 'path';
import { defineConfig } from 'vite';

const TARGET = process.env['HOFMANN_SERVER'] ?? 'http://localhost:8080';

export default defineConfig({
  build: {
    outDir: 'dist-demo',
    rollupOptions: {
      input: resolve(__dirname, 'demo.html'),
    },
  },
  server: {
    port: 5173,
    open: '/demo.html',
    proxy: {
      '/opaque': { target: TARGET, changeOrigin: true },
      '/oprf':   { target: TARGET, changeOrigin: true },
      '/api':    { target: TARGET, changeOrigin: true },
    },
  },
});
