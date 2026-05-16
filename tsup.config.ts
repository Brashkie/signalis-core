import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: false,
  target: 'node18',
  outDir: 'dist',
  // El binario nativo está fuera del bundle
  external: ['../index.js', '../index.cjs', './native'],
  // Genera extensiones EXPLÍCITAS para que Node no se confunda:
  //   .cjs → siempre CommonJS
  //   .mjs → siempre ESM
  // Esto evita el conflicto con "type": "commonjs" en package.json
  outExtension({ format }) {
    return {
      js: format === 'cjs' ? '.cjs' : '.mjs',
    };
  },
});
