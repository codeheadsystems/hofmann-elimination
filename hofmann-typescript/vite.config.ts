import { resolve } from 'path';
import { defineConfig } from 'vitest/config';
import dts from 'vite-plugin-dts';

export default defineConfig({
  plugins: [
    dts({
      include: ['src/**/*'],
      outDir: 'dist',
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'HofmannTypescript',
      fileName: 'hofmann-typescript',
      formats: ['es', 'umd'],
    },
    rollupOptions: {
      external: ['@noble/curves', '@noble/hashes'],
      output: {
        globals: {
          '@noble/curves': 'NobleCurves',
          '@noble/hashes': 'NobleHashes',
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
