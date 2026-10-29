import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { host: 'localhost', port: 5173, strictPort: true, proxy: { '/api': 'http://localhost:5180' } },
  preview: { host: 'localhost', port: 4173, proxy: { '/api': 'http://localhost:5180' } },
});
