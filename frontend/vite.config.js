import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The local launcher passes its selected backend port here. No provider keys
// belong in VITE_* variables: those are bundled into the browser application.
const backendUrl = process.env.ETAP_BACKEND_URL || 'http://127.0.0.1:5000';

export default defineConfig({
  plugins: [react()],
  server: {
    // SECURITY: Strictly bound to loopback. Never expose with --host or 0.0.0.0 on shared/demo Wi-Fi
    // to prevent Windows alternate-path server.fs.deny traversal (GHSA-fx2h-pf6j-xcff).
    // For external demos on other devices, serve the static production build (npm run build).
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/openapi.json': { target: backendUrl, changeOrigin: true },
      '/sandbox': { target: backendUrl, changeOrigin: true },
      '/analyze': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/health': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/chat': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/investigations': {
        target: backendUrl,
        changeOrigin: true,
      },
    },
  },
});
