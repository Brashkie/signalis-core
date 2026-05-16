import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['__tests__/**/*.test.ts'],
    deps: {
      interopDefault: true,
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'html', 'json-summary', 'lcov'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.d.ts',
        'src/types.ts',           // Solo tipos + branding zero-cost
        '**/*.config.ts',
        '**/node_modules/**',
        '**/dist/**',
        '**/target/**',
      ],
      // Umbrales realistas para crypto library:
      // - statements/lines: 95% (los catch blocks son difíciles de cubrir sin mocking)
      // - branches: 80% (incluye catch branches)
      // - functions: 95%
      thresholds: {
        statements: 95,
        branches: 80,
        functions: 95,
        lines: 95,
      },
      all: true,
      clean: true,
    },
  },
});
