import {defineConfig} from 'vite';

export default defineConfig({
  base: './',
  publicDir: 'public',
  build: {
    minify: false,
    sourcemap: false,
    target: 'es2022',
  },
});
