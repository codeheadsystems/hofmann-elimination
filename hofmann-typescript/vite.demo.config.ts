/**
 * Vite dev-server config for demo.html.
 *
 * Proxies /opaque and /oprf to the hofmann-server running on localhost:8080,
 * avoiding CORS issues when the demo page is served from a different port.
 *
 * Usage:
 *   npm run demo
 * which runs:
 *   vite --config vite.demo.config.ts
 */
import { defineConfig } from 'vite';

const TARGET = process.env['HOFMANN_SERVER'] ?? 'http://localhost:8080';

export default defineConfig({
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
