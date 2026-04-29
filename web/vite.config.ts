import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    // Allow access through Caddy (Host: localhost / ztp.example.com / etc.)
    // as well as direct vite (Host: localhost:5175). Setting `true` is fine
    // because the dev server is only published on a loopback port.
    allowedHosts: true,
    // The Go server proxies /v1/* — in dev we forward to it directly so the
    // browser sees same-origin requests and SSE works. Target is the
    // internal docker DNS name `server:8080` when run via compose, or
    // localhost:8080 for native dev.
    proxy: {
      '/v1': {
        target: process.env.VITE_ZTP_SERVER || 'http://localhost:8080',
        changeOrigin: true,
        // Vite proxy follows the target's TLS verification; we never use
        // HTTPS for the internal target so this is moot in compose.
        secure: false,
        ws: true
      }
    }
  }
});
