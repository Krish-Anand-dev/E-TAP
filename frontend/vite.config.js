import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // SECURITY: Strictly bound to loopback. Never expose with --host or 0.0.0.0 on shared/demo Wi-Fi
    // to prevent Windows alternate-path server.fs.deny traversal (GHSA-fx2h-pf6j-xcff).
    // For external demos on other devices, serve the static production build (npm run build).
    host: '127.0.0.1',
    port: 5173,
    proxy: Object.fromEntries(
      ['/analyze', '/health', '/ready', '/chat', '/investigations', '/sandbox', '/campaigns', '/preferences', '/recovery', '/analytics', '/baselines']
        .map((path) => [path, { target: 'http://127.0.0.1:5000', changeOrigin: true }]),
    ),
  },
});
